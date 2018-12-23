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
#include <signal.h>
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
#include "got_lib_object_cache.h"
#include "got_lib_object_parse.h"
#include "got_lib_privsep.h"
#include "got_lib_pack.h"

static volatile sig_atomic_t sigint_received;

static void
catch_sigint(int signo)
{
	sigint_received = 1;
}

static const struct got_error *
object_request(struct imsg *imsg, struct imsgbuf *ibuf, struct got_pack *pack,
    struct got_packidx *packidx, struct got_object_cache *objcache)
{
	const struct got_error *err = NULL;
	struct got_imsg_packed_object iobj;
	struct got_object *obj;
	struct got_object_id id;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(iobj))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&iobj, imsg->data, sizeof(iobj));
	memcpy(id.sha1, iobj.id, SHA1_DIGEST_LENGTH);

	err = got_packfile_open_object(&obj, pack, packidx, iobj.idx, &id);
	if (err)
		return err;
	obj->refcnt++;

	err = got_object_cache_add(objcache, &obj->id, obj);
	if (err)
		goto done;
	obj->refcnt++;

	err = got_privsep_send_obj(ibuf, obj);
done:
	got_object_close(obj);
	return err;
}

static const struct got_error *
get_object(struct got_object **obj, struct imsg *imsg, struct imsgbuf *ibuf,
    struct got_pack *pack, struct got_packidx *packidx,
    struct got_object_cache *objcache, int type)
{
	const struct got_error *err = NULL;
	struct got_object *iobj;

	err = got_privsep_get_imsg_obj(&iobj, imsg, ibuf);
	if (err)
		return err;

	if (iobj->type != type) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	if ((iobj->flags & GOT_OBJ_FLAG_PACKED) == 0)
		return got_error(GOT_ERR_OBJ_NOT_PACKED);

	*obj = got_object_cache_get(objcache, &iobj->id);
	if (*obj == NULL) {
		err = got_packfile_open_object(obj, pack, packidx,
		    iobj->pack_idx, &iobj->id);
		if (err)
			goto done;
	}
	(*obj)->refcnt++;
done:
	got_object_close(iobj);
	return err;
}

static const struct got_error *
commit_request(struct imsg *imsg, struct imsgbuf *ibuf, struct got_pack *pack,
    struct got_packidx *packidx, struct got_object_cache *objcache)
{
	const struct got_error *err = NULL;
	struct got_imsg_packed_object iobj;
	struct got_object *obj;
	struct got_commit_object *commit = NULL;
	uint8_t *buf;
	size_t len;
	struct got_object_id id;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(iobj))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&iobj, imsg->data, sizeof(iobj));
	memcpy(id.sha1, iobj.id, SHA1_DIGEST_LENGTH);

	err = got_packfile_open_object(&obj, pack, packidx, iobj.idx, &id);
	if (err)
		return err;

	err = got_packfile_extract_object_to_mem(&buf, &len, obj, pack);
	if (err)
		return err;

	obj->size = len;
	err = got_object_parse_commit(&commit, buf, len);
	free(buf);
	if (err) {
		got_object_close(obj);
		return err;
	}

	err = got_privsep_send_commit(ibuf, commit);
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
    struct got_packidx *packidx, struct got_object_cache *objcache)
{
	const struct got_error *err = NULL;
	struct got_object *obj = NULL;
	struct got_tree_object *tree = NULL;
	uint8_t *buf;
	size_t len;

	err = get_object(&obj, imsg, ibuf, pack, packidx, objcache,
	    GOT_OBJ_TYPE_TREE);
	if (err)
		return err;

	err = got_packfile_extract_object_to_mem(&buf, &len, obj, pack);
	if (err)
		return err;

	obj->size = len;
	err = got_object_parse_tree(&tree, buf, len);
	free(buf);

	err = got_privsep_send_tree(ibuf, tree);
	if (obj)
		got_object_close(obj);
	got_object_tree_close(tree);
	if (err) {
		if (err->code == GOT_ERR_PRIVSEP_PIPE)
			err = NULL;
		else
			got_privsep_send_error(ibuf, err);
	}

	return err;
}

static const struct got_error *
receive_file(FILE **f, struct imsgbuf *ibuf, int imsg_code)
{
	const struct got_error *err;
	struct imsg imsg;
	size_t datalen;

	err = got_privsep_recv_imsg(&imsg, ibuf, 0);
	if (err)
		return err;

	if (imsg.hdr.type != imsg_code) {
		err = got_error(GOT_ERR_PRIVSEP_MSG);
		goto done;
	}

	datalen = imsg.hdr.len - IMSG_HEADER_SIZE;
	if (datalen != 0) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}
	if (imsg.fd == -1) {
		err = got_error(GOT_ERR_PRIVSEP_NO_FD);
		goto done;
	}

	*f = fdopen(imsg.fd, "w+");
	if (*f == NULL) {
		close(imsg.fd);
		err = got_error_from_errno();
		goto done;
	}
done:
	imsg_free(&imsg);
	return err;
}

static const struct got_error *
blob_request(struct imsg *imsg, struct imsgbuf *ibuf, struct got_pack *pack,
    struct got_packidx *packidx, struct got_object_cache *objcache)
{
	const struct got_error *err = NULL;
	struct got_object *obj = NULL;
	FILE *outfile = NULL, *basefile = NULL, *accumfile = NULL;

	err = get_object(&obj, imsg, ibuf, pack, packidx, objcache,
	    GOT_OBJ_TYPE_BLOB);
	if (err)
		return err;

	err = receive_file(&outfile, ibuf, GOT_IMSG_BLOB_OUTFD);
	if (err)
		return err;
	err = receive_file(&basefile, ibuf, GOT_IMSG_TMPFD);
	if (err)
		return err;
	err = receive_file(&accumfile, ibuf, GOT_IMSG_TMPFD);
	if (err)
		return err;

	err = got_packfile_extract_object(pack, obj, outfile, basefile,
	    accumfile);
	if (err)
		goto done;

	err = got_privsep_send_blob(ibuf, obj->size);
done:
	if (outfile)
		fclose(outfile);
	if (basefile)
		fclose(basefile);
	if (accumfile)
		fclose(accumfile);
	if (obj)
		got_object_close(obj);
	if (err && err->code != GOT_ERR_PRIVSEP_PIPE)
		got_privsep_send_error(ibuf, err);

	return err;
}

static const struct got_error *
tag_request(struct imsg *imsg, struct imsgbuf *ibuf, struct got_pack *pack,
    struct got_packidx *packidx, struct got_object_cache *objcache)
{
	const struct got_error *err = NULL;
	struct got_object *obj = NULL;
	struct got_tag_object *tag = NULL;
	uint8_t *buf;
	size_t len;

	err = get_object(&obj, imsg, ibuf, pack, packidx, objcache,
	    GOT_OBJ_TYPE_TAG);
	if (err)
		return err;

	err = got_packfile_extract_object_to_mem(&buf, &len, obj, pack);
	if (err)
		return err;

	obj->size = len;
	err = got_object_parse_tag(&tag, buf, len);
	free(buf);

	err = got_privsep_send_tag(ibuf, tag);
	if (obj)
		got_object_close(obj);
	got_object_tag_close(tag);
	if (err) {
		if (err->code == GOT_ERR_PRIVSEP_PIPE)
			err = NULL;
		else
			got_privsep_send_error(ibuf, err);
	}

	return err;
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
	if (lseek(p->fd, 0, SEEK_SET) == -1) {
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
	if (lseek(pack->fd, 0, SEEK_SET) == -1) {
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
	struct got_packidx *packidx = NULL;
	struct got_pack *pack = NULL;
	struct got_object_cache objcache;

	//static int attached;
	//while (!attached) sleep(1);

	signal(SIGINT, catch_sigint);

	imsg_init(&ibuf, GOT_IMSG_FD_CHILD);

	err = got_object_cache_init(&objcache, GOT_OBJECT_CACHE_TYPE_OBJ);
	if (err) {
		err = got_error_from_errno();
		got_privsep_send_error(&ibuf, err);
		return 1;
	}

#ifndef PROFILE
	/* revoke access to most system calls */
	if (pledge("stdio recvfd", NULL) == -1) {
		err = got_error_from_errno();
		got_privsep_send_error(&ibuf, err);
		return 1;
	}
#endif

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

		switch (imsg.hdr.type) {
		case GOT_IMSG_PACKED_OBJECT_REQUEST:
			err = object_request(&imsg, &ibuf, pack, packidx,
			    &objcache);
			break;
		case GOT_IMSG_COMMIT_REQUEST:
			err = commit_request(&imsg, &ibuf, pack, packidx,
			    &objcache);
			break;
		case GOT_IMSG_TREE_REQUEST:
			err = tree_request(&imsg, &ibuf, pack, packidx,
			   &objcache);
			break;
		case GOT_IMSG_BLOB_REQUEST:
			err = blob_request(&imsg, &ibuf, pack, packidx,
			   &objcache);
			break;
		case GOT_IMSG_TAG_REQUEST:
			err = tag_request(&imsg, &ibuf, pack, packidx,
			   &objcache);
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		if (imsg.fd != -1)
			close(imsg.fd);
		imsg_free(&imsg);
		if (err)
			break;
	}

	if (packidx)
		got_packidx_close(packidx);
	if (pack)
		got_pack_close(pack);
	got_object_cache_close(&objcache);
	imsg_clear(&ibuf);
	if (err) {
		if (!sigint_received && err->code != GOT_ERR_PRIVSEP_PIPE) {
			fprintf(stderr, "%s: %s\n", getprogname(), err->msg);
			got_privsep_send_error(&ibuf, err);
		}
	}
	close(GOT_IMSG_FD_CHILD);
	return err ? 1 : 0;
}
