/*
 * Copyright (c) 2017 Stefan Sperling <stsp@openbsd.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sha1.h>
#include <zlib.h>
#include <ctype.h>
#include <limits.h>

#include "got_error.h"
#include "got_object.h"
#include "got_repository.h"

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

#define GOT_OBJ_TAG_COMMIT	"commit"
#define GOT_OBJ_TAG_TREE	"tree"
#define GOT_OBJ_TAG_BLOB	"blob"

const char *
got_object_id_str(struct got_object_id *id, char *buf, size_t size)
{
	char *p = buf;
	char hex[3];
	int i;

	if (size < SHA1_DIGEST_STRING_LENGTH)
		return NULL;

	for (i = 0; i < SHA1_DIGEST_LENGTH; i++) {
		snprintf(hex, sizeof(hex), "%.2x", id->sha1[i]);
		p[0] = hex[0];
		p[1] = hex[1];
		p += 2;
	}
	p[0] = '\0';

	return buf;
}

struct got_zstream_buf {
	z_stream z;
	char *inbuf;
	size_t inlen;
	char *outbuf;
	size_t outlen;
	int flags;
#define GOT_ZSTREAM_F_HAVE_MORE 0x01
};

static void
inflate_end(struct got_zstream_buf *zb)
{
	free(zb->inbuf);
	free(zb->outbuf);
	inflateEnd(&zb->z);
}

static const struct got_error *
inflate_init(struct got_zstream_buf *zb, size_t bufsize)
{
	const struct got_error *err = NULL;

	memset(zb, 0, sizeof(*zb));

	zb->z.zalloc = Z_NULL;
	zb->z.zfree = Z_NULL;
	if (inflateInit(&zb->z) != Z_OK) {
		err = got_error(GOT_ERR_IO);
		goto done;
	}

	zb->inlen = zb->outlen = bufsize;

	zb->inbuf = calloc(1, zb->inlen);
	if (zb->inbuf == NULL) {
		err = got_error(GOT_ERR_NO_MEM);
		goto done;
	}

	zb->outbuf = calloc(1, zb->outlen);
	if (zb->outbuf == NULL) {
		err = got_error(GOT_ERR_NO_MEM);
		goto done;
	}

done:
	if (err)
		inflate_end(zb);
	return err;
}

static const struct got_error *
inflate_read(struct got_zstream_buf *zb, FILE *f, size_t *outlenp)
{
	size_t last_total_out = zb->z.total_out;
	z_stream *z = &zb->z;
	int n, ret;

	z->next_out = zb->outbuf;
	z->avail_out = zb->outlen;

	if (z->avail_in == 0 && (zb->flags & GOT_ZSTREAM_F_HAVE_MORE) == 0) {
		int i;
		n = fread(zb->inbuf, 1, zb->inlen, f);
		if (n == 0) {
			if (ferror(f))
				return got_error(GOT_ERR_IO);
			*outlenp = 0;
			return NULL;
		}
		z->next_in = zb->inbuf;
		z->avail_in = n;
	}

	ret = inflate(z, Z_SYNC_FLUSH);
	if (ret == Z_OK) {
		if (z->avail_out == 0)
			zb->flags |= GOT_ZSTREAM_F_HAVE_MORE;
		else
			zb->flags &= ~GOT_ZSTREAM_F_HAVE_MORE;
	} else if (ret != Z_STREAM_END)
		return got_error(GOT_ERR_DECOMPRESSION);

	*outlenp = z->total_out - last_total_out;
	return NULL;
}

static const struct got_error *
parse_obj_header(struct got_object **obj, char *buf, size_t len)
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
	size_t size = 0;
	int i;
	char *p = strchr(buf, '\0');

	if (p == NULL)
		return got_error(GOT_ERR_BAD_OBJ_HDR);

	for (i = 0; i < nitems(obj_tags); i++) {
		const char *tag = obj_tags[i];
		const char *errstr;

		if (strncmp(buf, tag, strlen(tag)) != 0)
			continue;

		type = obj_types[i];
		if (len <= strlen(tag))
			return got_error(GOT_ERR_BAD_OBJ_HDR);
		size = strtonum(buf + strlen(tag), 0, LONG_MAX, &errstr);
		if (errstr != NULL)
			return got_error(GOT_ERR_BAD_OBJ_HDR);
		break;
	}

	if (type == 0)
		return got_error(GOT_ERR_BAD_OBJ_HDR);

	*obj = calloc(1, sizeof(**obj));
	(*obj)->type = type;
	(*obj)->size = size;
	return NULL;
}

static const struct got_error *
read_object_header(struct got_object **obj, struct got_repository *repo,
    const char *path)
{
	const struct got_error *err;
	FILE *f;
	struct got_zstream_buf zb;
	char *p;
	size_t outlen;
	int i, ret;

	f = fopen(path, "rb");
	if (f == NULL)
		return got_error(GOT_ERR_BAD_PATH);

	err = inflate_init(&zb, 64);
	if (err) {
		fclose(f);
		return err;
	}

	err = inflate_read(&zb, f, &outlen);
	if (err)
		goto done;

	err = parse_obj_header(obj, zb.outbuf, outlen);
done:
	inflate_end(&zb);
	fclose(f);
	return err;
}

const struct got_error *
got_object_open(struct got_object **obj, struct got_repository *repo,
    struct got_object_id *id)
{
	const struct got_error *err = NULL;
	char *path_objects = got_repo_get_path_objects(repo);
	char hex[SHA1_DIGEST_STRING_LENGTH];
	char *path = NULL;

	if (path_objects == NULL)
		return got_error(GOT_ERR_NO_MEM);

	got_object_id_str(id, hex, sizeof(hex));

	if (asprintf(&path, "%s/%.2x/%s",
	    path_objects, id->sha1[0], hex + 2) == -1) {
		err = got_error(GOT_ERR_NO_MEM);
		goto done;
	}

	err = read_object_header(obj, repo, path);
	if (err == NULL)
		memcpy((*obj)->id.sha1, id->sha1, SHA1_DIGEST_LENGTH);

done:
	free(path);
	free(path_objects);
	return err;
}

void
got_object_close(struct got_object *obj)
{
	free(obj);
}
