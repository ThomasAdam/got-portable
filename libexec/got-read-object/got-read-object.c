/*
 * Copyright (c) 2018 Stefan Sperling <stsp@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/limits.h>

#include <stdint.h>
#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sha1.h>
#include <zlib.h>

#include "got_error.h"
#include "got_object.h"

#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_privsep.h"

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

#define GOT_OBJ_TAG_COMMIT	"commit"
#define GOT_OBJ_TAG_TREE	"tree"
#define GOT_OBJ_TAG_BLOB	"blob"

static const struct got_error *
parse_object_header(struct got_object **obj, char *buf, size_t len)
{
	const char *obj_tags[] = {
		GOT_OBJ_TAG_COMMIT,
		GOT_OBJ_TAG_TREE,
		GOT_OBJ_TAG_BLOB
	};
	const int obj_types[] = {
		GOT_OBJ_TYPE_COMMIT,
		GOT_OBJ_TYPE_TREE,
		GOT_OBJ_TYPE_BLOB,
	};
	int type = 0;
	size_t size = 0, hdrlen = 0;
	int i;
	char *p = strchr(buf, '\0');

	if (p == NULL)
		return got_error(GOT_ERR_BAD_OBJ_HDR);

	hdrlen = strlen(buf) + 1 /* '\0' */;

	for (i = 0; i < nitems(obj_tags); i++) {
		const char *tag = obj_tags[i];
		size_t tlen = strlen(tag);
		const char *errstr;

		if (strncmp(buf, tag, tlen) != 0)
			continue;

		type = obj_types[i];
		if (len <= tlen)
			return got_error(GOT_ERR_BAD_OBJ_HDR);
		size = strtonum(buf + tlen, 0, LONG_MAX, &errstr);
		if (errstr != NULL)
			return got_error(GOT_ERR_BAD_OBJ_HDR);
		break;
	}

	if (type == 0)
		return got_error(GOT_ERR_BAD_OBJ_HDR);

	*obj = calloc(1, sizeof(**obj));
	if (*obj == NULL)
		return got_error_from_errno();
	(*obj)->type = type;
	(*obj)->hdrlen = hdrlen;
	(*obj)->size = size;
	return NULL;
}

static const struct got_error *
read_object_header(struct got_object **obj, int fd)
{
	const struct got_error *err;
	struct got_zstream_buf zb;
	char *buf;
	const size_t zbsize = 64;
	size_t outlen, totlen;
	int nbuf = 1;

	buf = malloc(zbsize);
	if (buf == NULL)
		return got_error_from_errno();

	err = got_inflate_init(&zb, buf, zbsize);
	if (err)
		return err;

	totlen = 0;
	do {
		err = got_inflate_read_fd(&zb, fd, &outlen);
		if (err)
			goto done;
		if (outlen == 0)
			break;
		totlen += outlen;
		if (strchr(zb.outbuf, '\0') == NULL) {
			char *newbuf;
			nbuf++;
			newbuf = recallocarray(buf, nbuf - 1, nbuf, zbsize);
			if (newbuf == NULL) {
				err = got_error_from_errno();
				goto done;
			}
			buf = newbuf;
			zb.outbuf = newbuf + totlen;
			zb.outlen = (nbuf * zbsize) - totlen;
		}
	} while (strchr(zb.outbuf, '\0') == NULL);

	err = parse_object_header(obj, buf, totlen);
done:
	free(buf);
	got_inflate_end(&zb);
	return err;
}


int
main(int argc, char *argv[])
{
	const struct got_error *err = NULL;
	struct got_object *obj = NULL;
	struct imsg imsg;
	struct imsgbuf ibuf;
	size_t datalen;

	imsg_init(&ibuf, GOT_IMSG_FD_CHILD);

	/* revoke access to most system calls */
	if (pledge("stdio recvfd", NULL) == -1) {
		err = got_error_from_errno();
		got_privsep_send_error(&ibuf, err);
		return 1;
	}

	while (1) {
		err = got_privsep_recv_imsg(&imsg, &ibuf, 0);
		if (err) {
			if (imsg.hdr.len == 0)
				err = NULL;
			break;
		}

		if (imsg.hdr.type == GOT_IMSG_STOP)
			break;

		if (imsg.hdr.type != GOT_IMSG_OBJECT_REQUEST) {
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			goto done;
		}

		datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
		if (datalen != 0) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}

		err = read_object_header(&obj, imsg.fd);
		if (err)
			goto done;

		err = got_privsep_send_obj(&ibuf, obj, 0);
done:
		close(imsg.fd);
		imsg_free(&imsg);
		if (obj)
			got_object_close(obj);
		if (err) {
			got_privsep_send_error(&ibuf, err);
			break;
		}
	}

	imsg_clear(&ibuf);
	if (err)
		fprintf(stderr, "%s: %s\n", getprogname(), err->msg);
	close(GOT_IMSG_FD_CHILD);
	return err ? 1 : 0;
}
