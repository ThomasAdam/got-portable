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
#include <sys/mman.h>

#include <limits.h>
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
#include "got_lib_pack.h"

static const struct got_error *
object_request(struct imsg *imsg, struct imsgbuf *ibuf, struct got_pack *pack,
    struct got_packidx *packidx)
{
	const struct got_error *err = NULL;
	struct got_imsg_packed_object iobj;
	struct got_object *obj;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(iobj))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&iobj, imsg->data, sizeof(iobj));

	err = got_packfile_open_object(&obj, pack, packidx, iobj.idx, NULL);
	if (err)
		return err;

	err = got_privsep_send_obj(ibuf, obj);
	got_object_close(obj);
	return err;
}

static const struct got_error *
commit_request(struct imsg *imsg, struct imsgbuf *ibuf, struct got_pack *pack,
    struct got_packidx *packidx)
{
	const struct got_error *err = NULL;
	struct got_object *obj = NULL;
	struct got_commit_object *commit = NULL;
	uint8_t *buf;
	size_t len;

	err = got_privsep_get_imsg_obj(&obj, imsg, ibuf);
	if (err)
		return err;

	if (obj->type != GOT_OBJ_TYPE_COMMIT)
		return got_error(GOT_ERR_OBJ_TYPE);

	err = got_packfile_extract_object_to_mem(&buf, &len, obj, pack);
	if (err)
		return err;

	obj->size = len;
	err = got_object_parse_commit(&commit, buf, len);
	free(buf);

	err = got_privsep_send_commit(ibuf, commit);
	if (obj)
		got_object_close(obj);
	got_object_commit_close(commit);
	if (err) {
		if (err->code == GOT_ERR_PRIVSEP_PIPE)
			err = NULL;
		else
			got_privsep_send_error(ibuf, err);
	}

	return err;
}

static const struct got_error *
tree_request(struct imsg *imsg, struct imsgbuf *ibuf, struct got_pack *pack,
    struct got_packidx *packidx)
{
	return got_error(GOT_ERR_NOT_IMPL);
}

static const struct got_error *
blob_request(struct imsg *imsg, struct imsgbuf *ibuf, struct got_pack *pack,
    struct got_packidx *packidx)
{
	return got_error(GOT_ERR_NOT_IMPL);
}

static const struct got_error *
receive_packidx(struct got_packidx **packidx, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	struct got_imsg_packidx ipackidx;
	size_t datalen;
	struct got_packidx *p;

	*packidx = NULL;

	err = got_privsep_recv_imsg(&imsg, ibuf, 0);
	if (err)
		return err;

	p = calloc(1, sizeof(*p));
	if (p == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	if (imsg.hdr.type != GOT_IMSG_PACKIDX) {
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		goto done;
	}

	if (imsg.fd == -1) {
		err = got_error(GOT_ERR_PRIVSEP_NO_FD);
		goto done;
	}

	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ipackidx)) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}
	memcpy(&ipackidx, imsg.data, sizeof(ipackidx));

	p->len = ipackidx.len;
	p->fd = dup(imsg.fd);
	if (p->fd == -1) {
		err = got_error_from_errno();
		goto done;
	}

#ifndef GOT_PACK_NO_MMAP
	p->map = mmap(NULL, p->len, PROT_READ, MAP_PRIVATE, p->fd, 0);
	if (p->map == MAP_FAILED)
		p->map = NULL; /* fall back to read(2) */
#endif
	err = got_packidx_init_hdr(p, 1);
done:
	if (err) {
		if (imsg.fd != -1)
			close(imsg.fd);
		got_packidx_close(p);
	} else
		*packidx = p;
	imsg_free(&imsg);
	return err;
}

static const struct got_error *
receive_pack(struct got_pack **packp, struct imsgbuf *ibuf)
{
	const struct got_error *err = NULL;
	struct imsg imsg;
	struct got_imsg_pack ipack;
	size_t datalen;
	struct got_pack *pack;

	*packp = NULL;

	err = got_privsep_recv_imsg(&imsg, ibuf, 0);
	if (err)
		return err;

	pack = calloc(1, sizeof(*pack));
	if (pack == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	if (imsg.hdr.type != GOT_IMSG_PACK) {
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		goto done;
	}

	if (imsg.fd == -1) {
		err = got_error(GOT_ERR_PRIVSEP_NO_FD);
		goto done;
	}

	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(ipack)) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}
	memcpy(&ipack, imsg.data, sizeof(ipack));

	pack->filesize = ipack.filesize;
	pack->fd = dup(imsg.fd);
	if (pack->fd == -1) {
		err = got_error_from_errno();
		goto done;
	}
	pack->path_packfile = strdup(ipack.path_packfile);
	if (pack->path_packfile == NULL) {
		err = got_error_from_errno();
		goto done;
	}

#ifndef GOT_PACK_NO_MMAP
	pack->map = mmap(NULL, pack->filesize, PROT_READ, MAP_PRIVATE,
	    pack->fd, 0);
	if (pack->map == MAP_FAILED)
		pack->map = NULL; /* fall back to read(2) */
#endif
done:
	if (err) {
		if (imsg.fd != -1)
			close(imsg.fd);
		free(pack);
	} else
		*packp = pack;
	imsg_free(&imsg);
	return err;
}

int
main(int argc, char *argv[])
{
	const struct got_error *err = NULL;
	struct imsgbuf ibuf;
	struct imsg imsg;
	struct got_packidx *packidx;
	struct got_pack *pack;

	//static int attached;
	//while (!attached) sleep(1);

	imsg_init(&ibuf, GOT_IMSG_FD_CHILD);

	/* revoke access to most system calls */
	if (pledge("stdio recvfd", NULL) == -1) {
		err = got_error_from_errno();
		got_privsep_send_error(&ibuf, err);
		return 1;
	}

	err = receive_packidx(&packidx, &ibuf);
	if (err) {
		got_privsep_send_error(&ibuf, err);
		return 1;
	}

	err = receive_pack(&pack, &ibuf);
	if (err) {
		got_privsep_send_error(&ibuf, err);
		return 1;
	}

	while (1) {
		imsg.fd = -1;

		err = got_privsep_recv_imsg(&imsg, &ibuf, 0);
		if (err) {
			if (err->code == GOT_ERR_PRIVSEP_PIPE)
				err = NULL;
			break;
		}

		if (imsg.hdr.type == GOT_IMSG_STOP)
			break;

		switch (imsg.hdr.type) {
		case GOT_IMSG_PACKED_OBJECT_REQUEST:
			err = object_request(&imsg, &ibuf, pack, packidx);
			break;
		case GOT_IMSG_COMMIT_REQUEST:
			err = commit_request(&imsg, &ibuf, pack, packidx);
			break;
		case GOT_IMSG_TREE_REQUEST:
			err = tree_request(&imsg, &ibuf, pack, packidx);
			break;
		case GOT_IMSG_BLOB_REQUEST:
			err = blob_request(&imsg, &ibuf, pack, packidx);
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		if (imsg.fd != -1)
			close(imsg.fd);
		imsg_free(&imsg);
		if (err) {
			if (err->code == GOT_ERR_PRIVSEP_PIPE)
				err = NULL;
			else
				got_privsep_send_error(&ibuf, err);
			break;
		}
	}

	got_pack_close(pack);
	imsg_clear(&ibuf);
	if (err)
		fprintf(stderr, "%s: %s\n", getprogname(), err->msg);
	close(GOT_IMSG_FD_CHILD);
	return err ? 1 : 0;
}
