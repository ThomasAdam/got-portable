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
#include <sys/syslimits.h>

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
#include "got_lib_object_parse.h"
#include "got_lib_privsep.h"

static const struct got_error *
read_commit_data(uint8_t **p, size_t *len, struct got_object *obj, FILE *f)
{
	const struct got_error *err;

	if (obj->flags & GOT_OBJ_FLAG_PACKED)
		err = got_read_file_to_mem(p, len, f);
	else
		err = got_inflate_to_mem(p, len, f);
	if (err)
		return err;

	if (*len < obj->hdrlen + obj->size) {
		free(*p);
		*p = NULL;
		*len = 0;
		return got_error(GOT_ERR_BAD_OBJ_DATA);
	}

	/* Skip object header. */
	*len -= obj->hdrlen;
	return NULL;
}

static const struct got_error *
read_commit_object(struct got_commit_object **commit, struct got_object *obj,
    FILE *f)
{
	const struct got_error *err;
	uint8_t *p;
	size_t len;

	err = read_commit_data(&p, &len, obj, f);
	if (err)
		return err;

	err = got_object_parse_commit(commit, p + obj->hdrlen, len);
	free(p);
	return err;
}

static const struct got_error *
read_commit_object_mini(struct got_mini_commit_object **commit,
    struct got_object *obj, FILE *f)
{
	const struct got_error *err;
	size_t len;
	uint8_t *p;

	err = read_commit_data(&p, &len, obj, f);
	if (err)
		return err;

	err = got_object_parse_mini_commit(commit, p + obj->hdrlen, len);
	free(p);
	return err;
}

int
main(int argc, char *argv[])
{
	const struct got_error *err = NULL;
	struct imsgbuf ibuf;
	size_t datalen;

	imsg_init(&ibuf, GOT_IMSG_FD_CHILD);

#ifndef PROFILE
	/* revoke access to most system calls */
	if (pledge("stdio recvfd", NULL) == -1) {
		err = got_error_from_errno();
		got_privsep_send_error(&ibuf, err);
		return 1;
	}
#endif

	while (1) {
		struct imsg imsg;
		struct got_imsg_object iobj;
		FILE *f = NULL;
		struct got_object *obj = NULL;
		int mini = 0;
	
		err = got_privsep_recv_imsg(&imsg, &ibuf, 0);
		if (err) {
			if (err->code == GOT_ERR_PRIVSEP_PIPE)
				err = NULL;
			break;
		}

		if (imsg.hdr.type == GOT_IMSG_STOP)
			break;

		switch (imsg.hdr.type) {
			case GOT_IMSG_COMMIT_REQUEST:
				mini = 0;
				break;
			case GOT_IMSG_MINI_COMMIT_REQUEST:
				mini = 1;
				break;
			default:
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				goto done;
		}

		datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
		if (datalen != sizeof(iobj)) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}

		memcpy(&iobj, imsg.data, sizeof(iobj));
		if (iobj.type != GOT_OBJ_TYPE_COMMIT) {
			err = got_error(GOT_ERR_OBJ_TYPE);
			goto done;
		}

		if (imsg.fd == -1) {
			err = got_error(GOT_ERR_PRIVSEP_NO_FD);
			goto done;
		}

		obj = calloc(1, sizeof(*obj));
		if (obj == NULL) {
			err = got_error_from_errno();
			goto done;
		}
		obj->type = iobj.type;
		obj->hdrlen = iobj.hdrlen;
		obj->size = iobj.size;

		/* Always assume file offset zero. */
		f = fdopen(imsg.fd, "rb");
		if (f == NULL) {
			err = got_error_from_errno();
			goto done;
		}

		if (mini) {
			struct got_mini_commit_object *commit;
			err = read_commit_object_mini(&commit, obj, f);
			if (err)
				goto done;
			err = got_privsep_send_mini_commit(&ibuf, commit, NULL);
			got_object_mini_commit_close(commit);
		} else {
			struct got_commit_object *commit;
			err = read_commit_object(&commit, obj, f);
			if (err)
				goto done;
			err = got_privsep_send_commit(&ibuf, commit);
			got_object_commit_close(commit);
		}
done:
		if (f)
			fclose(f);
		else if (imsg.fd != -1)
			close(imsg.fd);
		imsg_free(&imsg);
		if (obj)
			got_object_close(obj);
		if (err) {
			if (err->code == GOT_ERR_PRIVSEP_PIPE)
				err = NULL;
			else
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
