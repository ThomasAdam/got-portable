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
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/syslimits.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sha1.h>
#include <zlib.h>
#include <ctype.h>
#include <limits.h>
#include <imsg.h>
#include <time.h>

#include "got_error.h"
#include "got_object.h"
#include "got_repository.h"
#include "got_opentemp.h"

#include "got_lib_sha1.h"
#include "got_lib_delta.h"
#include "got_lib_pack.h"
#include "got_lib_path.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_privsep.h"
#include "got_lib_object_idcache.h"
#include "got_lib_object_cache.h"
#include "got_lib_object_parse.h"
#include "got_lib_repository.h"

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

int
got_object_id_cmp(struct got_object_id *id1, struct got_object_id *id2)
{
	return memcmp(id1->sha1, id2->sha1, SHA1_DIGEST_LENGTH);
}

struct got_object_id *
got_object_id_dup(struct got_object_id *id1)
{
	struct got_object_id *id2;

	id2 = malloc(sizeof(*id2));
	if (id2 == NULL)
		return NULL;
	memcpy(id2, id1, sizeof(*id2));
	return id2;
}

struct got_object_id *
got_object_get_id(struct got_object *obj)
{
	return &obj->id;
}

const struct got_error *
got_object_get_id_str(char **outbuf, struct got_object *obj)
{
	return got_object_id_str(outbuf, &obj->id);
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
object_path(char **path, struct got_object_id *id, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *hex = NULL;
	char *path_objects = got_repo_get_path_objects(repo);

	*path = NULL;

	if (path_objects == NULL)
		return got_error_from_errno();

	err = got_object_id_str(&hex, id);
	if (err)
		goto done;

	if (asprintf(path, "%s/%.2x/%s", path_objects,
	    id->sha1[0], hex + 2) == -1)
		err = got_error_from_errno();

done:
	free(hex);
	free(path_objects);
	return err;
}

static const struct got_error *
open_loose_object(int *fd, struct got_object *obj, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *path;

	err = object_path(&path, &obj->id, repo);
	if (err)
		return err;
	*fd = open(path, O_RDONLY | O_NOFOLLOW, GOT_DEFAULT_FILE_MODE);
	if (*fd == -1) {
		err = got_error_from_errno();
		goto done;
	}
done:
	free(path);
	return err;
}

static const struct got_error *
get_packfile_path(char **path_packfile, struct got_packidx *packidx)
{
	size_t size;

	/* Packfile path contains ".pack" instead of ".idx", so add one byte. */
	size = strlen(packidx->path_packidx) + 2;
	if (size < GOT_PACKFILE_NAMELEN + 1)
		return got_error(GOT_ERR_BAD_PATH);

	*path_packfile = calloc(size, sizeof(**path_packfile));
	if (*path_packfile == NULL)
		return got_error_from_errno();

	/* Copy up to and excluding ".idx". */
	if (strlcpy(*path_packfile, packidx->path_packidx,
	    size - strlen(GOT_PACKIDX_SUFFIX) - 1) >= size)
		return got_error(GOT_ERR_NO_SPACE);

	if (strlcat(*path_packfile, GOT_PACKFILE_SUFFIX, size) >= size)
		return got_error(GOT_ERR_NO_SPACE);

	return NULL;
}

static const struct got_error *
open_packed_object(struct got_object **obj, struct got_object_id *id,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_pack *pack = NULL;
	struct got_packidx *packidx = NULL;
	int idx;
	char *path_packfile;

	err = got_repo_search_packidx(&packidx, &idx, repo, id);
	if (err)
		return err;

	err = get_packfile_path(&path_packfile, packidx);
	if (err)
		return err;

	pack = got_repo_get_cached_pack(repo, path_packfile);
	if (pack == NULL) {
		err = got_repo_cache_pack(&pack, repo, path_packfile, packidx);
		if (err)
			goto done;
	}

	err = got_object_packed_read_privsep(obj, repo, pack, packidx, idx, id);
	if (err)
		goto done;

	err = got_repo_cache_pack(NULL, repo, (*obj)->path_packfile, packidx);
done:
	free(path_packfile);
	return err;
}

const struct got_error *
got_object_open(struct got_object **obj, struct got_repository *repo,
    struct got_object_id *id)
{
	const struct got_error *err = NULL;
	char *path;
	int fd;

	*obj = got_repo_get_cached_object(repo, id);
	if (*obj != NULL) {
		(*obj)->refcnt++;
		return NULL;
	}

	err = object_path(&path, id, repo);
	if (err)
		return err;

	fd = open(path, O_RDONLY | O_NOFOLLOW, GOT_DEFAULT_FILE_MODE);
	if (fd == -1) {
		if (errno != ENOENT) {
			err = got_error_from_errno();
			goto done;
		}
		err = open_packed_object(obj, id, repo);
		if (err)
			goto done;
		if (*obj == NULL)
			err = got_error(GOT_ERR_NO_OBJ);
	} else {
		err = got_object_read_header_privsep(obj, repo, fd);
		if (err)
			goto done;
		memcpy((*obj)->id.sha1, id->sha1, SHA1_DIGEST_LENGTH);
	}

	if (err == NULL) {
		(*obj)->refcnt++;
		err = got_repo_cache_object(repo, id, *obj);
	}
done:
	free(path);
	if (fd != -1)
		close(fd);
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

const struct got_error *
got_object_open_as_commit(struct got_commit_object **commit,
    struct got_repository *repo, struct got_object_id *id)
{
	const struct got_error *err;
	struct got_object *obj;

	*commit = NULL;

	err = got_object_open(&obj, repo, id);
	if (err)
		return err;
	if (got_object_get_type(obj) != GOT_OBJ_TYPE_COMMIT) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = got_object_commit_open(commit, repo, obj);
done:
	got_object_close(obj);
	return err;
}

const struct got_error *
got_object_qid_alloc(struct got_object_qid **qid, struct got_object_id *id)
{
	const struct got_error *err = NULL;

	*qid = calloc(1, sizeof(**qid));
	if (*qid == NULL)
		return got_error_from_errno();

	(*qid)->id = got_object_id_dup(id);
	if ((*qid)->id == NULL) {
		err = got_error_from_errno();
		got_object_qid_free(*qid);
		*qid = NULL;
		return err;
	}

	return NULL;
}

const struct got_error *
got_object_commit_open(struct got_commit_object **commit,
    struct got_repository *repo, struct got_object *obj)
{
	const struct got_error *err = NULL;

	*commit = got_repo_get_cached_commit(repo, &obj->id);
	if (*commit != NULL) {
		(*commit)->refcnt++;
		return NULL;
	}

	if (obj->type != GOT_OBJ_TYPE_COMMIT)
		return got_error(GOT_ERR_OBJ_TYPE);

	if (obj->flags & GOT_OBJ_FLAG_PACKED) {
		struct got_pack *pack;
		pack = got_repo_get_cached_pack(repo, obj->path_packfile);
		if (pack == NULL) {
			err = got_repo_cache_pack(&pack, repo,
			    obj->path_packfile, NULL);
			if (err)
				return err;
		}
		err = got_object_read_packed_commit_privsep(commit, obj, pack);
	} else {
		int fd;
		err = open_loose_object(&fd, obj, repo);
		if (err)
			return err;
		err = got_object_read_commit_privsep(commit, obj, fd, repo);
		close(fd);
	}

	if (err == NULL) {
		(*commit)->refcnt++;
		err = got_repo_cache_commit(repo, &obj->id, *commit);
	}

	return err;
}

const struct got_error *
got_object_tree_open(struct got_tree_object **tree,
    struct got_repository *repo, struct got_object *obj)
{
	const struct got_error *err = NULL;

	*tree = got_repo_get_cached_tree(repo, &obj->id);
	if (*tree != NULL) {
		(*tree)->refcnt++;
		return NULL;
	}

	if (obj->type != GOT_OBJ_TYPE_TREE)
		return got_error(GOT_ERR_OBJ_TYPE);

	if (obj->flags & GOT_OBJ_FLAG_PACKED) {
		struct got_pack *pack;
		pack = got_repo_get_cached_pack(repo, obj->path_packfile);
		if (pack == NULL) {
			err = got_repo_cache_pack(&pack, repo,
			    obj->path_packfile, NULL);
			if (err)
				return err;
		}
		err = got_object_read_packed_tree_privsep(tree, obj, pack);
	} else {
		int fd;
		err = open_loose_object(&fd, obj, repo);
		if (err)
			return err;
		err = got_object_read_tree_privsep(tree, obj, fd, repo);
		close(fd);
	}

	if (err == NULL) {
		(*tree)->refcnt++;
		err = got_repo_cache_tree(repo, &obj->id, *tree);
	}

	return err;
}

const struct got_error *
got_object_open_as_tree(struct got_tree_object **tree,
    struct got_repository *repo, struct got_object_id *id)
{
	const struct got_error *err;
	struct got_object *obj;

	*tree = NULL;

	err = got_object_open(&obj, repo, id);
	if (err)
		return err;
	if (got_object_get_type(obj) != GOT_OBJ_TYPE_TREE) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = got_object_tree_open(tree, repo, obj);
done:
	got_object_close(obj);
	return err;
}

const struct got_tree_entries *
got_object_tree_get_entries(struct got_tree_object *tree)
{
	return &tree->entries;
}

static const struct got_error *
read_packed_blob_privsep(size_t *size, int outfd, struct got_object *obj,
    struct got_pack *pack)
{
	const struct got_error *err = NULL;
	int outfd_child;
	int basefd, accumfd; /* temporary files for delta application */

	basefd = got_opentempfd();
	if (basefd == -1)
		return got_error_from_errno();
	accumfd = got_opentempfd();
	if (accumfd == -1)
		return got_error_from_errno();

	outfd_child = dup(outfd);
	if (outfd_child == -1)
		return got_error_from_errno();

	err = got_privsep_send_obj_req(pack->privsep_child->ibuf, -1, obj);
	if (err)
		return err;

	err = got_privsep_send_blob_outfd(pack->privsep_child->ibuf,
	    outfd_child);
	if (err) {
		close(outfd_child);
		return err;
	}
	err = got_privsep_send_tmpfd(pack->privsep_child->ibuf,
	    basefd);
	if (err) {
		close(basefd);
		close(accumfd);
		close(outfd_child);
		return err;
	}

	err = got_privsep_send_tmpfd(pack->privsep_child->ibuf,
	    accumfd);
	if (err) {
		close(accumfd);
		close(outfd_child);
		return err;
	}

	err = got_privsep_recv_blob(size, pack->privsep_child->ibuf);
	if (err)
		return err;

	if (lseek(outfd, SEEK_SET, 0) == -1)
		err = got_error_from_errno();

	return err;
}

const struct got_error *
got_object_blob_open(struct got_blob_object **blob,
    struct got_repository *repo, struct got_object *obj, size_t blocksize)
{
	const struct got_error *err = NULL;
	int outfd;
	size_t size;
	struct stat sb;

	if (obj->type != GOT_OBJ_TYPE_BLOB)
		return got_error(GOT_ERR_OBJ_TYPE);

	if (blocksize < obj->hdrlen)
		return got_error(GOT_ERR_NO_SPACE);

	*blob = calloc(1, sizeof(**blob));
	if (*blob == NULL)
		return got_error_from_errno();

	outfd = got_opentempfd();
	if (outfd == -1)
		return got_error_from_errno();

	(*blob)->read_buf = malloc(blocksize);
	if ((*blob)->read_buf == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	if (obj->flags & GOT_OBJ_FLAG_PACKED) {
		struct got_pack *pack;
		pack = got_repo_get_cached_pack(repo, obj->path_packfile);
		if (pack == NULL) {
			err = got_repo_cache_pack(&pack, repo,
			    obj->path_packfile, NULL);
			if (err)
				goto done;
		}
		err = read_packed_blob_privsep(&size, outfd, obj, pack);
		if (err)
			goto done;
		obj->size = size;
	} else {
		int infd;

		err = open_loose_object(&infd, obj, repo);
		if (err)
			goto done;

		err = got_object_read_blob_privsep(&size, outfd, infd, repo);
		close(infd);
		if (err)
			goto done;

		if (size != obj->hdrlen + obj->size) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}
	}

	if (fstat(outfd, &sb) == -1) {
		err = got_error_from_errno();
		goto done;
	}

	if (sb.st_size != obj->hdrlen + obj->size) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}

	(*blob)->f = fdopen(outfd, "rb");
	if ((*blob)->f == NULL) {
		err = got_error_from_errno();
		close(outfd);
		goto done;
	}

	(*blob)->hdrlen = obj->hdrlen;
	(*blob)->blocksize = blocksize;
	memcpy(&(*blob)->id.sha1, obj->id.sha1, SHA1_DIGEST_LENGTH);

done:
	if (err) {
		if (*blob) {
			if ((*blob)->f)
				fclose((*blob)->f);
			free((*blob)->read_buf);
			free(*blob);
			*blob = NULL;
		} else if (outfd != -1)
			close(outfd);
	}
	return err;
}

const struct got_error *
got_object_open_as_blob(struct got_blob_object **blob,
    struct got_repository *repo, struct got_object_id *id,
    size_t blocksize)
{
	const struct got_error *err;
	struct got_object *obj;

	*blob = NULL;

	err = got_object_open(&obj, repo, id);
	if (err)
		return err;
	if (got_object_get_type(obj) != GOT_OBJ_TYPE_BLOB) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = got_object_blob_open(blob, repo, obj, blocksize);
done:
	got_object_close(obj);
	return err;
}

void
got_object_blob_close(struct got_blob_object *blob)
{
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

	n = fread(blob->read_buf, 1, blob->blocksize, blob->f);
	if (n == 0 && ferror(blob->f))
		return got_ferror(blob->f, GOT_ERR_IO);
	*outlenp = n;
	return NULL;
}

const struct got_error *
got_object_blob_dump_to_file(size_t *total_len, size_t *nlines,
    FILE *outfile, struct got_blob_object *blob)
{
	const struct got_error *err = NULL;
	size_t len, hdrlen;
	const uint8_t *buf;
	int i;

	if (total_len)
		*total_len = 0;
	if (nlines)
		*nlines = 0;

	hdrlen = got_object_blob_get_hdrlen(blob);
	do {
		err = got_object_blob_read_block(&len, blob);
		if (err)
			return err;
		if (len == 0)
			break;
		if (total_len)
			*total_len += len;
		buf = got_object_blob_get_read_buf(blob);
		if (nlines) {
			for (i = 0; i < len; i++) {
				if (buf[i] == '\n')
					(*nlines)++;
			}
		}
		/* Skip blob object header first time around. */
		fwrite(buf + hdrlen, len - hdrlen, 1, outfile);
		hdrlen = 0;
	} while (len != 0);

	fflush(outfile);
	rewind(outfile);

	return NULL;
}

static struct got_tree_entry *
find_entry_by_name(struct got_tree_object *tree, const char *name, size_t len)
{
	struct got_tree_entry *te;

	SIMPLEQ_FOREACH(te, &tree->entries.head, entry) {
		if (strncmp(te->name, name, len) == 0)
			return te;
	}
	return NULL;
}

const struct got_error *
got_object_id_by_path(struct got_object_id **id, struct got_repository *repo,
    struct got_object_id *commit_id, const char *path)
{
	const struct got_error *err = NULL;
	struct got_commit_object *commit = NULL;
	struct got_tree_object *tree = NULL;
	struct got_tree_entry *te = NULL;
	const char *seg, *s;
	size_t seglen, len = strlen(path);

	*id = NULL;

	/* We are expecting an absolute in-repository path. */
	if (path[0] != '/')
		return got_error(GOT_ERR_NOT_ABSPATH);

	err = got_object_open_as_commit(&commit, repo, commit_id);
	if (err)
		goto done;

	/* Handle opening of root of commit's tree. */
	if (path[1] == '\0') {
		*id = got_object_id_dup(commit->tree_id);
		if (*id == NULL)
			err = got_error_from_errno();
		goto done;
	}

	err = got_object_open_as_tree(&tree, repo, commit->tree_id);
	if (err)
		goto done;

	s = path;
	s++; /* skip leading '/' */
	len--;
	seg = s;
	seglen = 0;
	while (len > 0) {
		struct got_tree_object *next_tree;

		if (*s != '/') {
			s++;
			len--;
			seglen++;
			if (*s)
				continue;
		}

		te = find_entry_by_name(tree, seg, seglen);
		if (te == NULL) {
			err = got_error(GOT_ERR_NO_OBJ);
			goto done;
		}

		if (len == 0)
			break;

		seg = s + 1;
		seglen = 0;
		s++;
		len--;
		if (*s) {
			err = got_object_open_as_tree(&next_tree, repo,
			    te->id);
			te = NULL;
			if (err)
				goto done;
			got_object_tree_close(tree);
			tree = next_tree;
		}
	}

	if (te) {
		*id = got_object_id_dup(te->id);
		if (*id == NULL)
			return got_error_from_errno();
	} else
		err = got_error(GOT_ERR_NO_OBJ);
done:
	if (commit)
		got_object_commit_close(commit);
	if (tree)
		got_object_tree_close(tree);
	return err;
}

const struct got_error *
got_object_tree_path_changed(int *changed,
    struct got_tree_object *tree01, struct got_tree_object *tree02,
    const char *path, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_tree_object *tree1 = NULL, *tree2 = NULL;
	struct got_tree_entry *te1 = NULL, *te2 = NULL;
	const char *seg, *s;
	size_t seglen, len = strlen(path);

	*changed = 0;

	/* We are expecting an absolute in-repository path. */
	if (path[0] != '/')
		return got_error(GOT_ERR_NOT_ABSPATH);

	/* We not do support comparing the root path. */
	if (path[1] == '\0')
		return got_error(GOT_ERR_BAD_PATH);

	tree1 = tree01;
	tree2 = tree02;
	s = path;
	s++; /* skip leading '/' */
	len--;
	seg = s;
	seglen = 0;
	while (len > 0) {
		struct got_tree_object *next_tree1, *next_tree2;

		if (*s != '/') {
			s++;
			len--;
			seglen++;
			if (*s)
				continue;
		}

		te1 = find_entry_by_name(tree1, seg, seglen);
		if (te1 == NULL) {
			err = got_error(GOT_ERR_NO_OBJ);
			goto done;
		}

		te2 = find_entry_by_name(tree2, seg, seglen);
		if (te2 == NULL) {
			*changed = 1;
			goto done;
		}

		if (te1->mode != te2->mode) {
			*changed = 1;
			goto done;
		}

		if (got_object_id_cmp(te1->id, te2->id) == 0) {
			*changed = 0;
			goto done;
		}

		if (len == 0) { /* final path element */
			*changed = 1;
			goto done;
		}

		seg = s + 1;
		s++;
		len--;
		seglen = 0;
		if (*s) {
			err = got_object_open_as_tree(&next_tree1, repo,
			    te1->id);
			te1 = NULL;
			if (err)
				goto done;
			if (tree1 != tree01)
				got_object_tree_close(tree1);
			tree1 = next_tree1;

			err = got_object_open_as_tree(&next_tree2, repo,
			    te2->id);
			te2 = NULL;
			if (err)
				goto done;
			if (tree2 != tree02)
				got_object_tree_close(tree2);
			tree2 = next_tree2;
		}
	}
done:
	if (tree1 && tree1 != tree01)
		got_object_tree_close(tree1);
	if (tree2 && tree2 != tree02)
		got_object_tree_close(tree2);
	return err;
}
