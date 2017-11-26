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

#include <sys/stat.h>
#include <sys/queue.h>

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
#include "got_sha1.h"

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

#define GOT_OBJ_TAG_COMMIT	"commit"
#define GOT_OBJ_TAG_TREE	"tree"
#define GOT_OBJ_TAG_BLOB	"blob"

#define GOT_COMMIT_TAG_TREE		"tree "
#define GOT_COMMIT_TAG_PARENT		"parent "
#define GOT_COMMIT_TAG_AUTHOR		"author "
#define GOT_COMMIT_TAG_COMMITTER	"committer "

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
	(*obj)->type = type;
	(*obj)->hdrlen = hdrlen;
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

	err = parse_object_header(obj, zb.outbuf, outlen);
done:
	inflate_end(&zb);
	fclose(f);
	return err;
}

static const struct got_error *
object_path(char **path, struct got_object_id *id,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char hex[SHA1_DIGEST_STRING_LENGTH];
	char *path_objects = got_repo_get_path_objects(repo);

	if (path_objects == NULL)
		return got_error(GOT_ERR_NO_MEM);

	got_object_id_str(id, hex, sizeof(hex));

	if (asprintf(path, "%s/%.2x/%s", path_objects,
	    id->sha1[0], hex + 2) == -1)
		err = got_error(GOT_ERR_NO_MEM);

	free(path_objects);
	return err;
}

const struct got_error *
got_object_open(struct got_object **obj, struct got_repository *repo,
    struct got_object_id *id)
{
	const struct got_error *err = NULL;
	char *path = NULL;

	err = object_path(&path, id, repo);
	if (err)
		return err;

	err = read_object_header(obj, repo, path);
	if (err == NULL)
		memcpy((*obj)->id.sha1, id->sha1, SHA1_DIGEST_LENGTH);
done:
	free(path);
	return err;
}

void
got_object_close(struct got_object *obj)
{
	free(obj);
}

static int
commit_object_valid(struct got_commit_object *commit)
{
	int i;
	int n;

	if (commit == NULL)
		return 0;

	n = 0;
	for (i = 0; i < SHA1_DIGEST_LENGTH; i++) {
		if (commit->tree_id.sha1[i] == 0)
			n++;
	}
	if (n == SHA1_DIGEST_LENGTH)
		return 0;

	return 1;
}

static const struct got_error *
parse_commit_object(struct got_commit_object **commit, char *buf, size_t len)
{
	const struct got_error *err = NULL;
	char *s = buf;
	size_t tlen;
	ssize_t remain = (ssize_t)len;
 
	*commit = calloc(1, sizeof(**commit));
	if (*commit == NULL)
		return got_error(GOT_ERR_NO_MEM);

	SIMPLEQ_INIT(&(*commit)->parent_ids);

	tlen = strlen(GOT_COMMIT_TAG_TREE);
	if (strncmp(s, GOT_COMMIT_TAG_TREE, tlen) == 0) {
		remain -= tlen;
		if (remain < SHA1_DIGEST_STRING_LENGTH) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		s += tlen;
		if (!got_parse_sha1_digest((*commit)->tree_id.sha1, s)) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		remain -= SHA1_DIGEST_STRING_LENGTH;
		s += SHA1_DIGEST_STRING_LENGTH;
	} else {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}

	tlen = strlen(GOT_COMMIT_TAG_PARENT);
	while (strncmp(s, GOT_COMMIT_TAG_PARENT, tlen) == 0) {
		struct got_parent_id *pid;

		remain -= tlen;
		if (remain < SHA1_DIGEST_STRING_LENGTH) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}	

		pid = calloc(1, sizeof(*pid));
		if (pid == NULL) {
			err = got_error(GOT_ERR_NO_MEM);
			goto done;
		}
		s += tlen;
		if (!got_parse_sha1_digest(pid->id.sha1, s)) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		SIMPLEQ_INSERT_TAIL(&(*commit)->parent_ids, pid, entry);
		(*commit)->nparents++;

		s += SHA1_DIGEST_STRING_LENGTH;
	}

	tlen = strlen(GOT_COMMIT_TAG_AUTHOR);
	if (strncmp(s, GOT_COMMIT_TAG_AUTHOR, tlen) == 0) {
		char *p;

		remain -= tlen;
		if (remain <= 0) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		s += tlen;
		p = strchr(s, '\n');
		if (p == NULL) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		*p = '\0';
		(*commit)->author = strdup(s);
		if ((*commit)->author == NULL) {
			err = got_error(GOT_ERR_NO_MEM);
			goto done;
		}
		s += strlen((*commit)->author) + 1;
	}

	tlen = strlen(GOT_COMMIT_TAG_COMMITTER);
	if (strncmp(s, GOT_COMMIT_TAG_COMMITTER, tlen) == 0) {
		char *p;

		remain -= tlen;
		if (remain <= 0) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		s += tlen;
		p = strchr(s, '\n');
		if (p == NULL) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		*p = '\0';
		(*commit)->committer = strdup(s);
		if ((*commit)->committer == NULL) {
			err = got_error(GOT_ERR_NO_MEM);
			goto done;
		}
		s += strlen((*commit)->committer) + 1;
	}

	(*commit)->logmsg = strdup(s);
done:
	if (err)
		got_object_commit_close(*commit);
	return err;
}

static void
tree_entry_close(struct got_tree_entry *te)
{
	free(te->name);
	free(te);
}

static const char *
mode_trailer(mode_t mode)
{
	if (S_ISDIR(mode))
		return "/";

	return "";
}

static const struct got_error *
parse_tree_entry(struct got_tree_entry **te, size_t *elen, char *buf,
    size_t maxlen)
{
	char *p = buf, *space;
	const struct got_error *err = NULL;
	char hex[SHA1_DIGEST_STRING_LENGTH];

	*te = calloc(1, sizeof(**te));
	if (*te == NULL)
		return got_error(GOT_ERR_NO_MEM);

	*elen = strlen(buf) + 1;
	if (*elen > maxlen) {
		free(*te);
		return got_error(GOT_ERR_BAD_OBJ_DATA);
	}

	space = strchr(buf, ' ');
	if (space == NULL) {
		free(*te);
		return got_error(GOT_ERR_BAD_OBJ_DATA);
	}
	while (*p != ' ') {
		if (*p < '0' && *p > '7') {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		(*te)->mode <<= 3;
		(*te)->mode |= *p - '0';
		p++;
	}

	(*te)->name = strdup(space + 1);
	if (*elen > maxlen || maxlen - *elen < SHA1_DIGEST_LENGTH) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}
	buf += strlen(buf) + 1;
	memcpy((*te)->id.sha1, buf, SHA1_DIGEST_LENGTH);
	*elen += SHA1_DIGEST_LENGTH;

	printf("%s %s%s\n", got_object_id_str(&(*te)->id, hex, sizeof(hex)),
	    (*te)->name, mode_trailer((*te)->mode));
done:
	if (err)
		tree_entry_close(*te);
	return err;
}

static const struct got_error *
open_tree_recursive(struct got_object_id *id, struct got_repository *repo)
{
	struct got_object *obj;
	struct got_tree_object *tree;
	const struct got_error *err;

	err = got_object_open(&obj, repo, id);
	if (err)
		return err;
	if (obj->type != GOT_OBJ_TYPE_TREE)
		return got_error(GOT_ERR_OBJ_TYPE);

	err = got_object_tree_open(&tree, repo, obj);
	if (err) {
		got_object_close(obj);
		return err;
	}

	got_object_tree_close(tree);
	got_object_close(obj);
	return NULL;
}

static const struct got_error *
parse_tree_object(struct got_tree_object **tree, struct got_repository *repo,
    char *buf, size_t len)
{
	size_t remain = len;
	int nentries;

	*tree = calloc(1, sizeof(**tree));
	if (*tree == NULL)
		return got_error(GOT_ERR_NO_MEM);

	SIMPLEQ_INIT(&(*tree)->entries);

	while (remain > 0) {
		struct got_tree_entry *te;
		size_t elen;

		parse_tree_entry(&te, &elen, buf, remain);
		(*tree)->nentries++;
		SIMPLEQ_INSERT_TAIL(&(*tree)->entries, te, entry);
		if (S_ISDIR(te->mode)) {
			const struct got_error *err;
			err = open_tree_recursive(&te->id, repo);
			if (err) {
				got_object_tree_close(*tree);
				return err;
			}
		}
		buf += elen;
		remain -= elen;
	}
	printf("\n");

	if (remain != 0) {
		got_object_tree_close(*tree);
		return got_error(GOT_ERR_BAD_OBJ_DATA);
	}

	return NULL;
}

static const struct got_error *
read_commit_object(struct got_commit_object **commit,
    struct got_repository *repo, struct got_object *obj, const char *path)
{
	const struct got_error *err = NULL;
	FILE *f;
	struct got_zstream_buf zb;
	size_t len;
	char *p;
	int i, ret;

	f = fopen(path, "rb");
	if (f == NULL)
		return got_error(GOT_ERR_BAD_PATH);

	err = inflate_init(&zb, 8192);
	if (err) {
		fclose(f);
		return err;
	}

	do {
		err = inflate_read(&zb, f, &len);
		if (err || len == 0)
			break;
	} while (len < obj->hdrlen + obj->size);

	if (len < obj->hdrlen + obj->size) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}

	/* Skip object header. */
	len -= obj->hdrlen;
	err = parse_commit_object(commit, zb.outbuf + obj->hdrlen, len);
done:
	inflate_end(&zb);
	fclose(f);
	return err;
}

const struct got_error *
got_object_commit_open(struct got_commit_object **commit,
    struct got_repository *repo, struct got_object *obj)
{
	const struct got_error *err = NULL;
	char *path = NULL;

	if (obj->type != GOT_OBJ_TYPE_COMMIT)
		return got_error(GOT_ERR_OBJ_TYPE);

	err = object_path(&path, &obj->id, repo);
	if (err)
		return err;

	err = read_commit_object(commit, repo, obj, path);
	free(path);
	return err;
}

void
got_object_commit_close(struct got_commit_object *commit)
{
	struct got_parent_id *pid;

	while (!SIMPLEQ_EMPTY(&commit->parent_ids)) {
		pid = SIMPLEQ_FIRST(&commit->parent_ids);
		SIMPLEQ_REMOVE_HEAD(&commit->parent_ids, entry);
		free(pid);
	}

	free(commit->author);
	free(commit->committer);
	free(commit->logmsg);
	free(commit);
}

static const struct got_error *
read_tree_object(struct got_tree_object **tree,
    struct got_repository *repo, struct got_object *obj, const char *path)
{
	const struct got_error *err = NULL;
	FILE *f;
	struct got_zstream_buf zb;
	size_t len;
	char *p;
	int i, ret;

	f = fopen(path, "rb");
	if (f == NULL)
		return got_error(GOT_ERR_BAD_PATH);

	err = inflate_init(&zb, 8192);
	if (err) {
		fclose(f);
		return err;
	}

	do {
		err = inflate_read(&zb, f, &len);
		if (err || len == 0)
			break;
	} while (len < obj->hdrlen + obj->size);

	if (len < obj->hdrlen + obj->size) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}

	/* Skip object header. */
	len -= obj->hdrlen;
	err = parse_tree_object(tree, repo, zb.outbuf + obj->hdrlen, len);
done:
	inflate_end(&zb);
	fclose(f);
	return err;
}

const struct got_error *
got_object_tree_open(struct got_tree_object **tree,
    struct got_repository *repo, struct got_object *obj)
{
	const struct got_error *err = NULL;
	char *path = NULL;

	if (obj->type != GOT_OBJ_TYPE_TREE)
		return got_error(GOT_ERR_OBJ_TYPE);

	err = object_path(&path, &obj->id, repo);
	if (err)
		return err;

	err = read_tree_object(tree, repo, obj, path);
	free(path);
	return err;
}

void
got_object_tree_close(struct got_tree_object *tree)
{
}
