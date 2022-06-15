/*
 * Copyright (c) 2018, 2019, 2020 Stefan Sperling <stsp@openbsd.org>
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
#include <fcntl.h>
#include <limits.h>
#include <sha1.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uuid.h>

#include "got_cancel.h"
#include "got_error.h"
#include "got_reference.h"
#include "got_path.h"
#include "got_worktree.h"
#include "got_repository.h"
#include "got_gotconfig.h"
#include "got_object.h"

#include "got_lib_worktree.h"
#include "got_lib_gotconfig.h"

static const struct got_error *
read_meta_file(char **content, const char *path_got, const char *name)
{
	const struct got_error *err = NULL;
	char *path;
	int fd = -1;
	ssize_t n;
	struct stat sb;

	*content = NULL;

	if (asprintf(&path, "%s/%s", path_got, name) == -1) {
		err = got_error_from_errno("asprintf");
		path = NULL;
		goto done;
	}

	fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd == -1) {
		if (errno == ENOENT)
			err = got_error_path(path, GOT_ERR_WORKTREE_META);
		else
			err = got_error_from_errno2("open", path);
		goto done;
	}
	if (flock(fd, LOCK_SH | LOCK_NB) == -1) {
		err = (errno == EWOULDBLOCK ? got_error(GOT_ERR_WORKTREE_BUSY)
		    : got_error_from_errno2("flock", path));
		goto done;
	}

	if (fstat(fd, &sb) != 0) {
		err = got_error_from_errno2("fstat", path);
		goto done;
	}
	*content = calloc(1, sb.st_size);
	if (*content == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}

	n = read(fd, *content, sb.st_size);
	if (n != sb.st_size) {
		err = (n == -1 ? got_error_from_errno2("read", path) :
		    got_error_path(path, GOT_ERR_WORKTREE_META));
		goto done;
	}
	if ((*content)[sb.st_size - 1] != '\n') {
		err = got_error_path(path, GOT_ERR_WORKTREE_META);
		goto done;
	}
	(*content)[sb.st_size - 1] = '\0';

done:
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno2("close", path_got);
	free(path);
	if (err) {
		free(*content);
		*content = NULL;
	}
	return err;
}

static const struct got_error *
open_worktree(struct got_worktree **worktree, const char *path)
{
	const struct got_error *err = NULL;
	char *path_got;
	char *formatstr = NULL;
	char *uuidstr = NULL;
	char *path_lock = NULL;
	char *base_commit_id_str = NULL;
	int version, fd = -1;
	const char *errstr;
	struct got_repository *repo = NULL;
	uint32_t uuid_status;

	*worktree = NULL;

	if (asprintf(&path_got, "%s/%s", path, GOT_WORKTREE_GOT_DIR) == -1) {
		err = got_error_from_errno("asprintf");
		path_got = NULL;
		goto done;
	}

	if (asprintf(&path_lock, "%s/%s", path_got, GOT_WORKTREE_LOCK) == -1) {
		err = got_error_from_errno("asprintf");
		path_lock = NULL;
		goto done;
	}

	fd = open(path_lock, O_RDWR | O_EXLOCK | O_NONBLOCK | O_CLOEXEC);
	if (fd == -1) {
		err = (errno == EWOULDBLOCK ? got_error(GOT_ERR_WORKTREE_BUSY)
		    : got_error_from_errno2("open", path_lock));
		goto done;
	}

	err = read_meta_file(&formatstr, path_got, GOT_WORKTREE_FORMAT);
	if (err)
		goto done;

	version = strtonum(formatstr, 1, INT_MAX, &errstr);
	if (errstr) {
		err = got_error_msg(GOT_ERR_WORKTREE_META,
		    "could not parse work tree format version number");
		goto done;
	}
	if (version != GOT_WORKTREE_FORMAT_VERSION) {
		err = got_error(GOT_ERR_WORKTREE_VERS);
		goto done;
	}

	*worktree = calloc(1, sizeof(**worktree));
	if (*worktree == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}
	(*worktree)->lockfd = -1;

	(*worktree)->root_path = realpath(path, NULL);
	if ((*worktree)->root_path == NULL) {
		err = got_error_from_errno2("realpath", path);
		goto done;
	}
	err = read_meta_file(&(*worktree)->repo_path, path_got,
	    GOT_WORKTREE_REPOSITORY);
	if (err)
		goto done;

	err = read_meta_file(&(*worktree)->path_prefix, path_got,
	    GOT_WORKTREE_PATH_PREFIX);
	if (err)
		goto done;

	err = read_meta_file(&base_commit_id_str, path_got,
	    GOT_WORKTREE_BASE_COMMIT);
	if (err)
		goto done;

	err = read_meta_file(&uuidstr, path_got, GOT_WORKTREE_UUID);
	if (err)
		goto done;
	uuid_from_string(uuidstr, &(*worktree)->uuid, &uuid_status);
	if (uuid_status != uuid_s_ok) {
		err = got_error_uuid(uuid_status, "uuid_from_string");
		goto done;
	}

	err = got_repo_pack_fds_open(&(*worktree)->pack_fds);
	if (err)
		goto done;

	err = got_repo_open(&repo, (*worktree)->repo_path, NULL,
	    (*worktree)->pack_fds);
	if (err)
		goto done;

	err = got_object_resolve_id_str(&(*worktree)->base_commit_id, repo,
	    base_commit_id_str);
	if (err)
		goto done;

	err = read_meta_file(&(*worktree)->head_ref_name, path_got,
	    GOT_WORKTREE_HEAD_REF);
	if (err)
		goto done;

	if (asprintf(&(*worktree)->gotconfig_path, "%s/%s/%s",
	    (*worktree)->root_path,
	    GOT_WORKTREE_GOT_DIR, GOT_GOTCONFIG_FILENAME) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	err = got_gotconfig_read(&(*worktree)->gotconfig,
	    (*worktree)->gotconfig_path);

	(*worktree)->root_fd = open((*worktree)->root_path,
	    O_DIRECTORY | O_CLOEXEC);
	if ((*worktree)->root_fd == -1) {
		err = got_error_from_errno2("open", (*worktree)->root_path);
		goto done;
	}
done:
	if (repo) {
		const struct got_error *close_err = got_repo_close(repo);
		if (err == NULL)
			err = close_err;
	}
	free(path_got);
	free(path_lock);
	free(base_commit_id_str);
	free(uuidstr);
	free(formatstr);
	if (err) {
		if (fd != -1)
			close(fd);
		if (*worktree != NULL)
			got_worktree_close(*worktree);
		*worktree = NULL;
	} else
		(*worktree)->lockfd = fd;

	return err;
}

const struct got_error *
got_worktree_open(struct got_worktree **worktree, const char *path)
{
	const struct got_error *err = NULL;
	char *worktree_path;

	worktree_path = strdup(path);
	if (worktree_path == NULL)
		return got_error_from_errno("strdup");

	for (;;) {
		char *parent_path;

		err = open_worktree(worktree, worktree_path);
		if (err && !(err->code == GOT_ERR_ERRNO && errno == ENOENT)) {
			free(worktree_path);
			return err;
		}
		if (*worktree) {
			free(worktree_path);
			return NULL;
		}
		if (worktree_path[0] == '/' && worktree_path[1] == '\0')
			break;
		err = got_path_dirname(&parent_path, worktree_path);
		if (err) {
			if (err->code != GOT_ERR_BAD_PATH) {
				free(worktree_path);
				return err;
			}
			break;
		}
		free(worktree_path);
		worktree_path = parent_path;
	}

	free(worktree_path);
	return got_error(GOT_ERR_NOT_WORKTREE);
}

const struct got_error *
got_worktree_close(struct got_worktree *worktree)
{
	const struct got_error *err = NULL;

	if (worktree->lockfd != -1) {
		if (close(worktree->lockfd) == -1)
			err = got_error_from_errno2("close",
			    got_worktree_get_root_path(worktree));
	}
	if (close(worktree->root_fd) == -1 && err == NULL)
		err = got_error_from_errno2("close",
		    got_worktree_get_root_path(worktree));
	if (worktree->pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(worktree->pack_fds);
		if (err == NULL)
			err = pack_err;
	}
	free(worktree->repo_path);
	free(worktree->path_prefix);
	free(worktree->base_commit_id);
	free(worktree->head_ref_name);
	free(worktree->root_path);
	free(worktree->gotconfig_path);
	got_gotconfig_free(worktree->gotconfig);
	free(worktree);
	return err;
}

const char *
got_worktree_get_root_path(struct got_worktree *worktree)
{
	return worktree->root_path;
}

const char *
got_worktree_get_repo_path(struct got_worktree *worktree)
{
	return worktree->repo_path;
}

const char *
got_worktree_get_path_prefix(struct got_worktree *worktree)
{
	return worktree->path_prefix;
}
