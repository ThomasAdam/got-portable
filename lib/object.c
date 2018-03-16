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

#include <sys/stat.h>
#include <sys/queue.h>

#include <errno.h>
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

#include "got_sha1_lib.h"
#include "got_delta_lib.h"
#include "got_pack_lib.h"
#include "got_zbuf_lib.h"
#include "got_object_lib.h"

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

const struct got_error *
got_object_id_str(char **outbuf, struct got_object_id *id)
{
	static const size_t len = SHA1_DIGEST_STRING_LENGTH;

	*outbuf = calloc(1, len);
	if (*outbuf == NULL)
		return got_error(GOT_ERR_NO_MEM);

	if (got_sha1_digest_to_str(id->sha1, *outbuf, len) == NULL) {
		free(*outbuf);
		*outbuf = NULL;
		return got_error(GOT_ERR_BAD_OBJ_ID_STR);
	}

	return NULL;
}

int
got_object_id_cmp(struct got_object_id *id1, struct got_object_id *id2)
{
	return memcmp(id1->sha1, id2->sha1, SHA1_DIGEST_LENGTH);
}

int
got_object_get_type(struct got_object *obj)
{
	switch (obj->type) {
	case GOT_OBJ_TYPE_COMMIT:
	case GOT_OBJ_TYPE_TREE:
	case GOT_OBJ_TYPE_BLOB:
	case GOT_OBJ_TYPE_TAG:
		return obj->type;
	default:
		abort();
		break;
	}

	/* not reached */
	return 0;
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
	if (*obj == NULL)
		return got_error(GOT_ERR_NO_MEM);
	(*obj)->type = type;
	(*obj)->hdrlen = hdrlen;
	(*obj)->size = size;
	return NULL;
}

static const struct got_error *
read_object_header(struct got_object **obj, struct got_repository *repo,
    FILE *f)
{
	const struct got_error *err;
	struct got_zstream_buf zb;
	char *buf;
	const size_t zbsize = 64;
	size_t outlen, totlen;
	int i;

	buf = calloc(zbsize, sizeof(char));
	if (buf == NULL)
		return got_error(GOT_ERR_NO_MEM);

	err = got_inflate_init(&zb, zbsize);
	if (err)
		return err;

	i = 0;
	totlen = 0;
	do {
		err = got_inflate_read(&zb, f, &outlen);
		if (err)
			goto done;
		if (strchr(zb.outbuf, '\0') == NULL) {
			buf = recallocarray(buf, 1 + i, 2 + i, zbsize);
			if (buf == NULL) {
				err = got_error(GOT_ERR_NO_MEM);
				goto done;
			}
		}
		memcpy(buf + totlen, zb.outbuf, outlen);
		totlen += outlen;
		i++;
	} while (strchr(zb.outbuf, '\0') == NULL);

	err = parse_object_header(obj, buf, totlen);
done:
	got_inflate_end(&zb);
	return err;
}

static const struct got_error *
object_path(char **path, struct got_object_id *id, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *hex;
	char *path_objects = got_repo_get_path_objects(repo);

	if (path_objects == NULL)
		return got_error(GOT_ERR_NO_MEM);

	err = got_object_id_str(&hex, id);
	if (err)
		return err;

	if (asprintf(path, "%s/%.2x/%s", path_objects,
	    id->sha1[0], hex + 2) == -1)
		err = got_error(GOT_ERR_NO_MEM);

	free(hex);
	free(path_objects);
	return err;
}

static const struct got_error *
open_loose_object(FILE **f, struct got_object *obj, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *path;

	err = object_path(&path, &obj->id, repo);
	if (err)
		return err;
	*f = fopen(path, "rb");
	if (*f == NULL) {
		err = got_error_from_errno();
		goto done;
	}
done:
	free(path);
	return err;
}

const struct got_error *
got_object_open(struct got_object **obj, struct got_repository *repo,
    struct got_object_id *id)
{
	const struct got_error *err = NULL;
	char *path;
	FILE *f;

	err = object_path(&path, id, repo);
	if (err)
		return err;

	f = fopen(path, "rb");
	if (f == NULL) {
		if (errno != ENOENT) {
			err = got_error_from_errno();
			goto done;
		}
		err = got_packfile_open_object(obj, id, repo);
		if (err)
			goto done;
		if (*obj == NULL)
			err = got_error(GOT_ERR_NO_OBJ);
	} else {
		err = read_object_header(obj, repo, f);
		if (err)
			goto done;
		memcpy((*obj)->id.sha1, id->sha1, SHA1_DIGEST_LENGTH);
	}
done:
	free(path);
	if (err && f)
		fclose(f);
	return err;

}

const struct got_error *
got_object_open_by_id_str(struct got_object **obj, struct got_repository *repo,
    const char *id_str)
{
	struct got_object_id id;

	if (!got_parse_sha1_digest(id.sha1, id_str))
		return got_error(GOT_ERR_BAD_OBJ_ID_STR);

	return got_object_open(obj, repo, &id);
}

void
got_object_close(struct got_object *obj)
{
	if (obj->flags & GOT_OBJ_FLAG_DELTIFIED) {
		struct got_delta *delta;
		while (!SIMPLEQ_EMPTY(&obj->deltas.entries)) {
			delta = SIMPLEQ_FIRST(&obj->deltas.entries);
			SIMPLEQ_REMOVE_HEAD(&obj->deltas.entries, entry);
			got_delta_close(delta);
		}
	}
	if (obj->flags & GOT_OBJ_FLAG_PACKED)
		free(obj->path_packfile);
	free(obj);
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
	(*commit)->tree_id = calloc(1, sizeof(*(*commit)->tree_id));
	if ((*commit)->tree_id == NULL) {
		free(*commit);
		*commit = NULL;
		return got_error(GOT_ERR_NO_MEM);
	}

	SIMPLEQ_INIT(&(*commit)->parent_ids);

	tlen = strlen(GOT_COMMIT_TAG_TREE);
	if (strncmp(s, GOT_COMMIT_TAG_TREE, tlen) == 0) {
		remain -= tlen;
		if (remain < SHA1_DIGEST_STRING_LENGTH) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			goto done;
		}
		s += tlen;
		if (!got_parse_sha1_digest((*commit)->tree_id->sha1, s)) {
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
		pid->id = calloc(1, sizeof(*pid->id));
		if (pid->id == NULL) {
			free(pid);
			err = got_error(GOT_ERR_NO_MEM);
			goto done;
		}
		s += tlen;
		if (!got_parse_sha1_digest(pid->id->sha1, s)) {
			err = got_error(GOT_ERR_BAD_OBJ_DATA);
			free(pid->id);
			free(pid);
			goto done;
		}
		SIMPLEQ_INSERT_TAIL(&(*commit)->parent_ids, pid, entry);
		(*commit)->nparents++;

		remain -= SHA1_DIGEST_STRING_LENGTH;
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
		remain -= strlen((*commit)->author) + 1;
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
		remain -= strlen((*commit)->committer) + 1;
	}

	(*commit)->logmsg = strndup(s, remain);
	if ((*commit)->logmsg == NULL) {
		err = got_error(GOT_ERR_NO_MEM);
		goto done;
	}
done:
	if (err) {
		got_object_commit_close(*commit);
		*commit = NULL;
	}
	return err;
}

static void
tree_entry_close(struct got_tree_entry *te)
{
	free(te->id);
	free(te->name);
	free(te);
}

static const struct got_error *
parse_tree_entry(struct got_tree_entry **te, size_t *elen, char *buf,
    size_t maxlen)
{
	char *p = buf, *space;
	const struct got_error *err = NULL;

	*te = calloc(1, sizeof(**te));
	if (*te == NULL)
		return got_error(GOT_ERR_NO_MEM);

	(*te)->id = calloc(1, sizeof(*(*te)->id));
	if ((*te)->id == NULL) {
		free(*te);
		*te = NULL;
		return got_error(GOT_ERR_NO_MEM);
	}

	*elen = strlen(buf) + 1;
	if (*elen > maxlen) {
		free(*te);
		*te = NULL;
		return got_error(GOT_ERR_BAD_OBJ_DATA);
	}

	space = strchr(buf, ' ');
	if (space == NULL) {
		free(*te);
		*te = NULL;
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
	memcpy((*te)->id->sha1, buf, SHA1_DIGEST_LENGTH);
	*elen += SHA1_DIGEST_LENGTH;
done:
	if (err) {
		tree_entry_close(*te);
		*te = NULL;
	}
	return err;
}

static const struct got_error *
parse_tree_object(struct got_tree_object **tree, struct got_repository *repo,
    uint8_t *buf, size_t len)
{
	const struct got_error *err;
	size_t remain = len;

	*tree = calloc(1, sizeof(**tree));
	if (*tree == NULL)
		return got_error(GOT_ERR_NO_MEM);

	SIMPLEQ_INIT(&(*tree)->entries);

	while (remain > 0) {
		struct got_tree_entry *te;
		size_t elen;

		err = parse_tree_entry(&te, &elen, buf, remain);
		if (err)
			return err;
		(*tree)->nentries++;
		SIMPLEQ_INSERT_TAIL(&(*tree)->entries, te, entry);
		buf += elen;
		remain -= elen;
	}

	if (remain != 0) {
		got_object_tree_close(*tree);
		return got_error(GOT_ERR_BAD_OBJ_DATA);
	}

	return NULL;
}

static const struct got_error *
read_to_mem(uint8_t **outbuf, size_t *outlen, FILE *f)
{
	const struct got_error *err = NULL;
	static const size_t blocksize = 512;
	size_t n, total, remain;
	uint8_t *buf;

	*outbuf = NULL;
	*outlen = 0;

	buf = calloc(1, blocksize);
	if (buf == NULL)
		return got_error(GOT_ERR_NO_MEM);

	remain = blocksize;
	total = 0;
	while (1) {
		if (remain == 0) {
			uint8_t *newbuf;
			newbuf = reallocarray(buf, 1, total + blocksize);
			if (newbuf == NULL) {
				err = got_error(GOT_ERR_NO_MEM);
				goto done;
			}
			buf = newbuf;
			remain += blocksize;
		}
		n = fread(buf + total, 1, remain, f);
		if (n == 0) {
			if (ferror(f)) {
				err = got_ferror(f, GOT_ERR_IO);
				goto done;
			}
			break; /* EOF */
		}
		remain -= n;
		total += n;
	};

done:
	if (err == NULL) {
		*outbuf = buf;
		*outlen = total;
	} else
		free(buf);
	return err;
}

static const struct got_error *
read_commit_object(struct got_commit_object **commit,
    struct got_repository *repo, struct got_object *obj, FILE *f)
{
	const struct got_error *err = NULL;
	size_t len;
	uint8_t *p;

	if (obj->flags & GOT_OBJ_FLAG_PACKED)
		err = read_to_mem(&p, &len, f);
	else
		err = got_inflate_to_mem(&p, &len, f);
	if (err)
		return err;

	if (len < obj->hdrlen + obj->size) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}

	/* Skip object header. */
	len -= obj->hdrlen;
	err = parse_commit_object(commit, p + obj->hdrlen, len);
	free(p);
done:
	return err;
}

const struct got_error *
got_object_commit_open(struct got_commit_object **commit,
    struct got_repository *repo, struct got_object *obj)
{
	const struct got_error *err = NULL;
	FILE *f;

	if (obj->type != GOT_OBJ_TYPE_COMMIT)
		return got_error(GOT_ERR_OBJ_TYPE);

	if (obj->flags & GOT_OBJ_FLAG_PACKED)
		err = got_packfile_extract_object(&f, obj, repo);
	else
		err = open_loose_object(&f, obj, repo);
	if (err)
		return err;

	err = read_commit_object(commit, repo, obj, f);
	fclose(f);
	return err;
}

void
got_object_commit_close(struct got_commit_object *commit)
{
	struct got_parent_id *pid;

	while (!SIMPLEQ_EMPTY(&commit->parent_ids)) {
		pid = SIMPLEQ_FIRST(&commit->parent_ids);
		SIMPLEQ_REMOVE_HEAD(&commit->parent_ids, entry);
		free(pid->id);
		free(pid);
	}

	free(commit->tree_id);
	free(commit->author);
	free(commit->committer);
	free(commit->logmsg);
	free(commit);
}

static const struct got_error *
read_tree_object(struct got_tree_object **tree,
    struct got_repository *repo, struct got_object *obj, FILE *f)
{
	const struct got_error *err = NULL;
	size_t len;
	uint8_t *p;

	if (obj->flags & GOT_OBJ_FLAG_PACKED)
		err = read_to_mem(&p, &len, f);
	else
		err = got_inflate_to_mem(&p, &len, f);
	if (err)
		return err;

	if (len < obj->hdrlen + obj->size) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}

	/* Skip object header. */
	len -= obj->hdrlen;
	err = parse_tree_object(tree, repo, p + obj->hdrlen, len);
	free(p);
done:
	return err;
}

const struct got_error *
got_object_tree_open(struct got_tree_object **tree,
    struct got_repository *repo, struct got_object *obj)
{
	const struct got_error *err = NULL;

	if (obj->type != GOT_OBJ_TYPE_TREE)
		return got_error(GOT_ERR_OBJ_TYPE);

	if (obj->flags & GOT_OBJ_FLAG_PACKED) {
		uint8_t *buf;
		size_t len;
		err = got_packfile_extract_object_to_mem(&buf, &len, obj, repo);
		if (err)
			return err;
		err = parse_tree_object(tree, repo, buf + obj->hdrlen, len);
		free(buf);
	} else {
		FILE *f;
		err = open_loose_object(&f, obj, repo);
		if (err)
			return err;
		err = read_tree_object(tree, repo, obj, f);
		fclose(f);
	}
	return err;
}

void
got_object_tree_close(struct got_tree_object *tree)
{
	struct got_tree_entry *te;

	while (!SIMPLEQ_EMPTY(&tree->entries)) {
		te = SIMPLEQ_FIRST(&tree->entries);
		SIMPLEQ_REMOVE_HEAD(&tree->entries, entry);
		tree_entry_close(te);
	}

	free(tree);
}

const struct got_error *
got_object_blob_open(struct got_blob_object **blob,
    struct got_repository *repo, struct got_object *obj, size_t blocksize)
{
	const struct got_error *err = NULL;

	if (obj->type != GOT_OBJ_TYPE_BLOB)
		return got_error(GOT_ERR_OBJ_TYPE);

	if (blocksize < obj->hdrlen)
		return got_error(GOT_ERR_NO_SPACE);

	*blob = calloc(1, sizeof(**blob));
	if (*blob == NULL)
		return got_error(GOT_ERR_NO_MEM);

	if (obj->flags & GOT_OBJ_FLAG_PACKED) {
		(*blob)->read_buf = calloc(1, blocksize);
		if ((*blob)->read_buf == NULL)
			return got_error(GOT_ERR_NO_MEM);
		err = got_packfile_extract_object(&((*blob)->f), obj, repo);
		if (err)
			return err;
	} else {
		err = open_loose_object(&((*blob)->f), obj, repo);
		if (err) {
			free(*blob);
			return err;
		}

		err = got_inflate_init(&(*blob)->zb, blocksize);
		if (err != NULL) {
			fclose((*blob)->f);
			free(*blob);
			return err;
		}

		(*blob)->read_buf = (*blob)->zb.outbuf;
		(*blob)->flags |= GOT_BLOB_F_COMPRESSED;
	}

	(*blob)->hdrlen = obj->hdrlen;
	(*blob)->blocksize = blocksize;
	memcpy(&(*blob)->id.sha1, obj->id.sha1, SHA1_DIGEST_LENGTH);

	return err;
}

void
got_object_blob_close(struct got_blob_object *blob)
{
	if (blob->flags & GOT_BLOB_F_COMPRESSED)
		got_inflate_end(&blob->zb);
	else
		free(blob->read_buf);
	fclose(blob->f);
	free(blob);
}

char *
got_object_blob_id_str(struct got_blob_object *blob, char *buf, size_t size)
{
	return got_sha1_digest_to_str(blob->id.sha1, buf, size);
}

size_t
got_object_blob_get_hdrlen(struct got_blob_object *blob)
{
	return blob->hdrlen;
}

const uint8_t *
got_object_blob_get_read_buf(struct got_blob_object *blob)
{
	return blob->read_buf;
}

const struct got_error *
got_object_blob_read_block(size_t *outlenp, struct got_blob_object *blob)
{
	size_t n;

	if (blob->flags & GOT_BLOB_F_COMPRESSED)
		return got_inflate_read(&blob->zb, blob->f, outlenp);

	n = fread(blob->read_buf, 1, blob->blocksize, blob->f);
	if (n == 0 && ferror(blob->f))
		return got_ferror(blob->f, GOT_ERR_IO);
	*outlenp = n;
	return NULL;
}
