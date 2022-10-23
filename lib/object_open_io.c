/*
 * Copyright (c) 2022 Stefan Sperling <stsp@openbsd.org>
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

#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/stat.h>

#include <errno.h>
#include <limits.h>
#include <sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "got_error.h"
#include "got_object.h"
#include "got_repository.h"
#include "got_path.h"

#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_object_cache.h"
#include "got_lib_object_parse.h"
#include "got_lib_pack.h"
#include "got_lib_repository.h"

const struct got_error *
got_object_open_packed(struct got_object **obj, struct got_object_id *id,
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

	err = got_packidx_get_packfile_path(&path_packfile,
	    packidx->path_packidx);
	if (err)
		return err;

	pack = got_repo_get_cached_pack(repo, path_packfile);
	if (pack == NULL) {
		err = got_repo_cache_pack(&pack, repo, path_packfile, packidx);
		if (err)
			goto done;
	}

	err = got_packfile_open_object(obj, pack, packidx, idx, id);
	if (err)
		return err;
	(*obj)->refcnt++;

	err = got_repo_cache_object(repo, id, *obj);
	if (err) {
		if (err->code == GOT_ERR_OBJ_EXISTS ||
		    err->code == GOT_ERR_OBJ_TOO_LARGE)
			err = NULL;
	}
done:
	free(path_packfile);
	return err;
}

const struct got_error *
got_object_open_from_packfile(struct got_object **obj, struct got_object_id *id,
    struct got_pack *pack, struct got_packidx *packidx, int obj_idx,
    struct got_repository *repo)
{
	return got_error(GOT_ERR_NOT_IMPL);
}

const struct got_error *
got_object_read_raw_delta(uint64_t *base_size, uint64_t *result_size,
    off_t *delta_size, off_t *delta_compressed_size, off_t *delta_offset,
    off_t *delta_out_offset, struct got_object_id **base_id, int delta_cache_fd,
    struct got_packidx *packidx, int obj_idx, struct got_object_id *id,
    struct got_repository *repo)
{
	return got_error(GOT_ERR_NOT_IMPL);
}

const struct got_error *
got_object_open(struct got_object **obj, struct got_repository *repo,
    struct got_object_id *id)
{
	const struct got_error *err = NULL;
	int fd;

	*obj = got_repo_get_cached_object(repo, id);
	if (*obj != NULL) {
		(*obj)->refcnt++;
		return NULL;
	}

	err = got_object_open_packed(obj, id, repo);
	if (err) {
		if (err->code != GOT_ERR_NO_OBJ)
			return err;
	} else
		return NULL;

	err = got_object_open_loose_fd(&fd, id, repo);
	if (err) {
		if (err->code == GOT_ERR_ERRNO && errno == ENOENT)
			err = got_error_no_obj(id);
		return err;
	}

	err = got_object_read_header(obj, fd);
	if (err)
		goto done;

	memcpy(&(*obj)->id, id, sizeof((*obj)->id));
	(*obj)->refcnt++;

	err = got_repo_cache_object(repo, id, *obj);
	if (err) {
		if (err->code == GOT_ERR_OBJ_EXISTS ||
		    err->code == GOT_ERR_OBJ_TOO_LARGE)
			err = NULL;
	}
done:
	if (close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	return err;
}

static const struct got_error *
wrap_fd(FILE **f, int wrapped_fd)
{
	const struct got_error *err = NULL;
	int fd;

	if (ftruncate(wrapped_fd, 0L) == -1)
		return got_error_from_errno("ftruncate");

	if (lseek(wrapped_fd, 0L, SEEK_SET) == -1)
		return got_error_from_errno("lseek");

	fd = dup(wrapped_fd);
	if (fd == -1)
		return got_error_from_errno("dup");

	*f = fdopen(fd, "w+");
	if (*f == NULL) {
		err = got_error_from_errno("fdopen");
		close(fd);
	}
	return err;
}

static const struct got_error *
read_packed_object_raw(uint8_t **outbuf, off_t *size, size_t *hdrlen,
    int outfd, struct got_pack *pack, struct got_packidx *packidx, int idx,
    struct got_object_id *id)
{
	const struct got_error *err = NULL;
	uint64_t raw_size = 0;
	struct got_object *obj;
	FILE *outfile = NULL, *basefile = NULL, *accumfile = NULL;

	*outbuf = NULL;
	*size = 0;
	*hdrlen = 0;

	err = got_packfile_open_object(&obj, pack, packidx, idx, id);
	if (err)
		return err;

	if (obj->flags & GOT_OBJ_FLAG_DELTIFIED) {
		err = got_pack_get_max_delta_object_size(&raw_size, obj, pack);
		if (err)
			goto done;
	} else
		raw_size = obj->size;

	if (raw_size <= GOT_DELTA_RESULT_SIZE_CACHED_MAX) {
		size_t len;
		err = got_packfile_extract_object_to_mem(outbuf, &len,
		    obj, pack);
		if (err)
			goto done;
		*size = (off_t)len;
	} else {
		/*
		 * XXX This uses 3 file extra descriptors for no good reason.
		 * We should have got_packfile_extract_object_to_fd().
		 */
		err = wrap_fd(&outfile, outfd);
		if (err)
			goto done;
		err = wrap_fd(&basefile, pack->basefd);
		if (err)
			goto done;
		err = wrap_fd(&accumfile, pack->accumfd);
		if (err)
			goto done;
		err = got_packfile_extract_object(pack, obj, outfile, basefile,
		    accumfile);
		if (err)
			goto done;
	}

	*hdrlen = obj->hdrlen;
done:
	got_object_close(obj);
	if (outfile && fclose(outfile) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (basefile && fclose(basefile) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (accumfile && fclose(accumfile) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	return err;

}

static void
put_raw_object_tempfile(struct got_raw_object *obj)
{
	struct got_repository *repo = obj->close_arg;

	if (obj->tempfile_idx != -1)
		got_repo_temp_fds_put(obj->tempfile_idx, repo);
}

/* *outfd must be initialized to -1 by caller */
const struct got_error *
got_object_raw_open(struct got_raw_object **obj, int *outfd,
    struct got_repository *repo, struct got_object_id *id)
{
	const struct got_error *err = NULL;
	struct got_packidx *packidx = NULL;
	int idx, tempfile_idx = -1;
	uint8_t *outbuf = NULL;
	off_t size = 0;
	size_t hdrlen = 0;
	char *path_packfile = NULL;

	*obj = got_repo_get_cached_raw_object(repo, id);
	if (*obj != NULL) {
		(*obj)->refcnt++;
		return NULL;
	}

	if (*outfd == -1) {
		int tempfd;

		err = got_repo_temp_fds_get(&tempfd, &tempfile_idx, repo);
		if (err)
			return err;

		/* Duplicate tempfile descriptor to allow use of fdopen(3). */
		*outfd = dup(tempfd);
		if (*outfd == -1) {
			got_repo_temp_fds_put(tempfile_idx, repo);
			return got_error_from_errno("dup");
		}
	}

	err = got_repo_search_packidx(&packidx, &idx, repo, id);
	if (err == NULL) {
		struct got_pack *pack = NULL;

		err = got_packidx_get_packfile_path(&path_packfile,
		    packidx->path_packidx);
		if (err)
			goto done;

		pack = got_repo_get_cached_pack(repo, path_packfile);
		if (pack == NULL) {
			err = got_repo_cache_pack(&pack, repo, path_packfile,
			    packidx);
			if (err)
				goto done;
		}
		err = read_packed_object_raw(&outbuf, &size, &hdrlen,
		    *outfd, pack, packidx, idx, id);
		if (err)
			goto done;
	} else if (err->code == GOT_ERR_NO_OBJ) {
		int fd;

		err = got_object_open_loose_fd(&fd, id, repo);
		if (err)
			goto done;
		err = got_object_read_raw(&outbuf, &size, &hdrlen,
		    GOT_DELTA_RESULT_SIZE_CACHED_MAX, *outfd, id, fd);
		if (close(fd) == -1 && err == NULL)
			err = got_error_from_errno("close");
		if (err)
			goto done;
	}

	err = got_object_raw_alloc(obj, outbuf, outfd, hdrlen, size);
	if (err)
		goto done;

	err = got_repo_cache_raw_object(repo, id, *obj);
	if (err) {
		if (err->code == GOT_ERR_OBJ_EXISTS ||
		    err->code == GOT_ERR_OBJ_TOO_LARGE)
			err = NULL;
	}
done:
	free(path_packfile);
	if (err) {
		if (*obj) {
			got_object_raw_close(*obj);
			*obj = NULL;
		}
		free(outbuf);
		if (tempfile_idx != -1)
			got_repo_temp_fds_put(tempfile_idx, repo);
	} else {
		(*obj)->tempfile_idx = tempfile_idx;
		(*obj)->close_cb = put_raw_object_tempfile;
		(*obj)->close_arg = repo;
	}
	return err;
}

static const struct got_error *
open_commit(struct got_commit_object **commit,
    struct got_repository *repo, struct got_object_id *id, int check_cache)
{
	const struct got_error *err = NULL;
	struct got_packidx *packidx = NULL;
	int idx;
	char *path_packfile = NULL;

	if (check_cache) {
		*commit = got_repo_get_cached_commit(repo, id);
		if (*commit != NULL) {
			(*commit)->refcnt++;
			return NULL;
		}
	} else
		*commit = NULL;

	err = got_repo_search_packidx(&packidx, &idx, repo, id);
	if (err == NULL) {
		struct got_pack *pack = NULL;
		struct got_object *obj;
		uint8_t *buf;
		size_t len;

		err = got_packidx_get_packfile_path(&path_packfile,
		    packidx->path_packidx);
		if (err)
			return err;

		pack = got_repo_get_cached_pack(repo, path_packfile);
		if (pack == NULL) {
			err = got_repo_cache_pack(&pack, repo, path_packfile,
			    packidx);
			if (err)
				goto done;
		}
		err = got_packfile_open_object(&obj, pack, packidx, idx, id);
		if (err)
			goto done;
		err = got_packfile_extract_object_to_mem(&buf, &len,
		    obj, pack);
		got_object_close(obj);
		if (err)
			goto done;
		err = got_object_parse_commit(commit, buf, len);
		free(buf);
	} else if (err->code == GOT_ERR_NO_OBJ) {
		int fd;

		err = got_object_open_loose_fd(&fd, id, repo);
		if (err)
			return err;
		err = got_object_read_commit(commit, fd, id, 0);
		if (close(fd) == -1 && err == NULL)
			err = got_error_from_errno("close");
		if (err)
			return err;
	}

	if (err == NULL) {
		(*commit)->refcnt++;
		err = got_repo_cache_commit(repo, id, *commit);
		if (err) {
			if (err->code == GOT_ERR_OBJ_EXISTS ||
			    err->code == GOT_ERR_OBJ_TOO_LARGE)
				err = NULL;
		}
	}
done:
	free(path_packfile);
	return err;
}

const struct got_error *
got_object_open_as_commit(struct got_commit_object **commit,
    struct got_repository *repo, struct got_object_id *id)
{
	*commit = got_repo_get_cached_commit(repo, id);
	if (*commit != NULL) {
		(*commit)->refcnt++;
		return NULL;
	}

	return open_commit(commit, repo, id, 0);
}

const struct got_error *
got_object_commit_open(struct got_commit_object **commit,
    struct got_repository *repo, struct got_object *obj)
{
	return open_commit(commit, repo, got_object_get_id(obj), 1);
}

static const struct got_error *
open_tree(struct got_tree_object **tree,
    struct got_repository *repo, struct got_object_id *id, int check_cache)
{
	const struct got_error *err = NULL;
	struct got_packidx *packidx = NULL;
	int idx;
	char *path_packfile = NULL;
	struct got_parsed_tree_entry *entries = NULL;
	size_t nentries = 0, nentries_alloc = 0, i;
	uint8_t *buf = NULL;

	if (check_cache) {
		*tree = got_repo_get_cached_tree(repo, id);
		if (*tree != NULL) {
			(*tree)->refcnt++;
			return NULL;
		}
	} else
		*tree = NULL;

	err = got_repo_search_packidx(&packidx, &idx, repo, id);
	if (err == NULL) {
		struct got_pack *pack = NULL;
		struct got_object *obj;
		size_t len;

		err = got_packidx_get_packfile_path(&path_packfile,
		    packidx->path_packidx);
		if (err)
			return err;

		pack = got_repo_get_cached_pack(repo, path_packfile);
		if (pack == NULL) {
			err = got_repo_cache_pack(&pack, repo, path_packfile,
			    packidx);
			if (err)
				goto done;
		}
		err = got_packfile_open_object(&obj, pack, packidx, idx, id);
		if (err)
			goto done;
		err = got_packfile_extract_object_to_mem(&buf, &len,
		    obj, pack);
		got_object_close(obj);
		if (err)
			goto done;
		err = got_object_parse_tree(&entries, &nentries,
		    &nentries_alloc, buf, len);
		if (err)
			goto done;
	} else if (err->code == GOT_ERR_NO_OBJ) {
		int fd;

		err = got_object_open_loose_fd(&fd, id, repo);
		if (err)
			return err;
		err = got_object_read_tree(&entries, &nentries,
		    &nentries_alloc, &buf, fd, id);
		if (close(fd) == -1 && err == NULL)
			err = got_error_from_errno("close");
		if (err)
			goto done;
	} else
		goto done;

	*tree = malloc(sizeof(**tree));
	if (*tree == NULL) {
		err = got_error_from_errno("malloc");
		goto done;
	}
	(*tree)->entries = calloc(nentries, sizeof(struct got_tree_entry));
	if ((*tree)->entries == NULL) {
		err = got_error_from_errno("malloc");
		goto done;
	}
	(*tree)->nentries = nentries;
	(*tree)->refcnt = 0;

	for (i = 0; i < nentries; i++) {
		struct got_parsed_tree_entry *pe = &entries[i];
		struct got_tree_entry *te = &(*tree)->entries[i];
	
		if (strlcpy(te->name, pe->name,
		    sizeof(te->name)) >= sizeof(te->name)) {
			err = got_error(GOT_ERR_NO_SPACE);
			goto done;
		}
		memcpy(te->id.sha1, pe->id, SHA1_DIGEST_LENGTH);
		te->mode = pe->mode;
		te->idx = i;
	}
done:
	free(path_packfile);
	free(entries);
	free(buf);
	if (err == NULL) {
		(*tree)->refcnt++;
		err = got_repo_cache_tree(repo, id, *tree);
		if (err) {
			if (err->code == GOT_ERR_OBJ_EXISTS ||
			    err->code == GOT_ERR_OBJ_TOO_LARGE)
				err = NULL;
		}
	}
	if (err) {
		if (*tree)
			free((*tree)->entries);
		free(*tree);
		*tree = NULL;
	}
	return err;
}

const struct got_error *
got_object_open_as_tree(struct got_tree_object **tree,
    struct got_repository *repo, struct got_object_id *id)
{
	*tree = got_repo_get_cached_tree(repo, id);
	if (*tree != NULL) {
		(*tree)->refcnt++;
		return NULL;
	}

	return open_tree(tree, repo, id, 0);
}

const struct got_error *
got_object_tree_open(struct got_tree_object **tree,
    struct got_repository *repo, struct got_object *obj)
{
	return open_tree(tree, repo, got_object_get_id(obj), 1);
}

const struct got_error *
got_object_open_as_blob(struct got_blob_object **blob,
    struct got_repository *repo, struct got_object_id *id, size_t blocksize,
    int outfd)
{
	return got_error(GOT_ERR_NOT_IMPL);
}

const struct got_error *
got_object_blob_open(struct got_blob_object **blob,
    struct got_repository *repo, struct got_object *obj, size_t blocksize,
    int outfd)
{
	return got_error(GOT_ERR_NOT_IMPL);
}

static const struct got_error *
open_tag(struct got_tag_object **tag, struct got_repository *repo,
    struct got_object_id *id, int check_cache)
{
	const struct got_error *err = NULL;
	struct got_packidx *packidx = NULL;
	int idx;
	char *path_packfile = NULL;
	struct got_object *obj = NULL;
	int obj_type = GOT_OBJ_TYPE_ANY;

	if (check_cache) {
		*tag = got_repo_get_cached_tag(repo, id);
		if (*tag != NULL) {
			(*tag)->refcnt++;
			return NULL;
		}
	} else
		*tag = NULL;

	err = got_repo_search_packidx(&packidx, &idx, repo, id);
	if (err == NULL) {
		struct got_pack *pack = NULL;
		uint8_t *buf = NULL;
		size_t len;

		err = got_packidx_get_packfile_path(&path_packfile,
		    packidx->path_packidx);
		if (err)
			return err;

		pack = got_repo_get_cached_pack(repo, path_packfile);
		if (pack == NULL) {
			err = got_repo_cache_pack(&pack, repo, path_packfile,
			    packidx);
			if (err)
				goto done;
		}

		/* Beware of "lightweight" tags: Check object type first. */
		err = got_packfile_open_object(&obj, pack, packidx, idx, id);
		if (err)
			goto done;
		obj_type = obj->type;
		if (obj_type != GOT_OBJ_TYPE_TAG) {
			err = got_error(GOT_ERR_OBJ_TYPE);
			got_object_close(obj);
			goto done;
		}
		err = got_packfile_extract_object_to_mem(&buf, &len,
		    obj, pack);
		got_object_close(obj);
		if (err)
			goto done;
		err = got_object_parse_tag(tag, buf, len);
		free(buf);
	} else if (err->code == GOT_ERR_NO_OBJ) {
		int fd;

		err = got_object_open_loose_fd(&fd, id, repo);
		if (err)
			return err;
		err = got_object_read_header(&obj, fd);
		if (close(fd) == -1 && err == NULL)
			err = got_error_from_errno("close");
		if (err)
			return err;
		obj_type = obj->type;
		got_object_close(obj);
		if (obj_type != GOT_OBJ_TYPE_TAG)
			return got_error(GOT_ERR_OBJ_TYPE);

		err = got_object_open_loose_fd(&fd, id, repo);
		if (err)
			return err;
		err = got_object_read_tag(tag, fd, id, 0);
		if (close(fd) == -1 && err == NULL)
			err = got_error_from_errno("close");
		if (err)
			return err;
	}

	if (err == NULL) {
		(*tag)->refcnt++;
		err = got_repo_cache_tag(repo, id, *tag);
		if (err) {
			if (err->code == GOT_ERR_OBJ_EXISTS ||
			    err->code == GOT_ERR_OBJ_TOO_LARGE)
				err = NULL;
		}
	}
done:
	free(path_packfile);
	return err;
}

const struct got_error *
got_object_open_as_tag(struct got_tag_object **tag,
    struct got_repository *repo, struct got_object_id *id)
{
	*tag = got_repo_get_cached_tag(repo, id);
	if (*tag != NULL) {
		(*tag)->refcnt++;
		return NULL;
	}

	return open_tag(tag, repo, id, 0);
}

const struct got_error *
got_object_tag_open(struct got_tag_object **tag,
    struct got_repository *repo, struct got_object *obj)
{
	return open_tag(tag, repo, got_object_get_id(obj), 1);
}
