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

#include <stdint.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zlib.h>

#include "got_compat.h"

#include "got_error.h"
#include "got_object.h"

#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_object_parse.h"
#include "got_lib_privsep.h"
#include "got_lib_sha1.h"

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

#define GOT_OBJ_TAG_COMMIT	"commit"
#define GOT_OBJ_TAG_TREE	"tree"
#define GOT_OBJ_TAG_BLOB	"blob"
#define GOT_OBJ_TAG_TAG		"tag"

static volatile sig_atomic_t sigint_received;

static void
catch_sigint(int signo)
{
	sigint_received = 1;
}

static const struct got_error *
send_raw_obj(struct imsgbuf *ibuf, struct got_object *obj,
    struct got_object_id *expected_id,
    int fd, int outfd)
{
	const struct got_error *err = NULL;
	uint8_t *data = NULL;
	size_t len = 0, consumed;
	FILE *f;
	struct got_object_id id;
	struct got_inflate_checksum csum;
	SHA1_CTX sha1_ctx;

	SHA1Init(&sha1_ctx);
	memset(&csum, 0, sizeof(csum));
	csum.output_sha1 = &sha1_ctx;

	if (lseek(fd, SEEK_SET, 0) == -1) {
		err = got_error_from_errno("lseek");
		close(fd);
		return err;
	}

	f = fdopen(fd, "r");
	if (f == NULL) {
		err = got_error_from_errno("fdopen");
		close(fd);
		return err;
	}

	if (obj->size + obj->hdrlen <= GOT_PRIVSEP_INLINE_OBJECT_DATA_MAX)
		err = got_inflate_to_mem(&data, &len, &consumed, &csum, f);
	else
		err = got_inflate_to_fd(&len, f, &csum, outfd);
	if (err)
		goto done;

	if (len < obj->hdrlen || len != obj->hdrlen + obj->size) {
		err = got_error(GOT_ERR_BAD_OBJ_HDR);
		goto done;
	}

	SHA1Final(id.sha1, &sha1_ctx);
	if (memcmp(expected_id->sha1, id.sha1, SHA1_DIGEST_LENGTH) != 0) {
		char buf[SHA1_DIGEST_STRING_LENGTH];
		err = got_error_fmt(GOT_ERR_OBJ_CSUM,
		    "checksum failure for object %s",
		    got_sha1_digest_to_str(expected_id->sha1, buf,
		    sizeof(buf)));
		goto done;
	}


	err = got_privsep_send_raw_obj(ibuf, obj->size, obj->hdrlen, data);

done:
	free(data);
	if (fclose(f) == EOF && err == NULL)
		err = got_error_from_errno("fclose");

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
	struct got_object_id expected_id;

	signal(SIGINT, catch_sigint);

	imsg_init(&ibuf, GOT_IMSG_FD_CHILD);

#ifndef PROFILE
	/* revoke access to most system calls */
	if (pledge("stdio recvfd", NULL) == -1) {
		err = got_error_from_errno("pledge");
		got_privsep_send_error(&ibuf, err);
		return 1;
	}

	/* revoke fs access */
	if (landlock_no_fs() == -1) {
		err = got_error_from_errno("landlock_no_fs");
		got_privsep_send_error(&ibuf, err);
		return 1;
	}
	if (cap_enter() == -1) {
		err = got_error_from_errno("cap_enter");
		got_privsep_send_error(&ibuf, err);
		return 1;
	}
#endif

	for (;;) {
		if (sigint_received) {
			err = got_error(GOT_ERR_CANCELLED);
			break;
		}

		err = got_privsep_recv_imsg(&imsg, &ibuf, 0);
		if (err) {
			if (err->code == GOT_ERR_PRIVSEP_PIPE)
				err = NULL;
			break;
		}

		if (imsg.hdr.type == GOT_IMSG_STOP)
			break;

		if (imsg.hdr.type != GOT_IMSG_OBJECT_REQUEST &&
		    imsg.hdr.type != GOT_IMSG_RAW_OBJECT_REQUEST) {
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			goto done;
		}

		datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
		if (datalen != sizeof(expected_id)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
		memcpy(&expected_id, imsg.data, sizeof(expected_id));

		if (imsg.fd == -1) {
			err = got_error(GOT_ERR_PRIVSEP_NO_FD);
			goto done;
		}

		err = got_object_read_header(&obj, imsg.fd);
		if (err)
			goto done;

		if (imsg.hdr.type == GOT_IMSG_RAW_OBJECT_REQUEST) {
			struct imsg imsg_outfd;

			err = got_privsep_recv_imsg(&imsg_outfd, &ibuf, 0);
			if (err) {
				if (imsg_outfd.hdr.len == 0)
					err = NULL;
				goto done;
			}

			if (imsg_outfd.hdr.type == GOT_IMSG_STOP) {
				imsg_free(&imsg_outfd);
				goto done;
			}

			if (imsg_outfd.hdr.type != GOT_IMSG_RAW_OBJECT_OUTFD) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				imsg_free(&imsg_outfd);
				goto done;
			}

			datalen = imsg_outfd.hdr.len - IMSG_HEADER_SIZE;
			if (datalen != 0) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				imsg_free(&imsg_outfd);
				goto done;
			}
			if (imsg_outfd.fd == -1) {
				err = got_error(GOT_ERR_PRIVSEP_NO_FD);
				imsg_free(&imsg_outfd);
				goto done;
			}
			err = send_raw_obj(&ibuf, obj, &expected_id,
			    imsg.fd, imsg_outfd.fd);
			imsg.fd = -1; /* imsg.fd is owned by send_raw_obj() */
			if (close(imsg_outfd.fd) == -1 && err == NULL)
				err = got_error_from_errno("close");
			imsg_free(&imsg_outfd);
			if (err)
				goto done;
		} else
			err = got_privsep_send_obj(&ibuf, obj);
done:
		if (imsg.fd != -1 && close(imsg.fd) == -1 && err == NULL)
			err = got_error_from_errno("close");
		imsg_free(&imsg);
		if (obj)
			got_object_close(obj);
		if (err)
			break;
	}

	imsg_clear(&ibuf);
	if (err) {
		if(!sigint_received && err->code != GOT_ERR_PRIVSEP_PIPE) {
			fprintf(stderr, "%s: %s\n", getprogname(), err->msg);
			got_privsep_send_error(&ibuf, err);
		}
	}
	if (close(GOT_IMSG_FD_CHILD) == -1 && err == NULL)
		err = got_error_from_errno("close");
	return err ? 1 : 0;
}
