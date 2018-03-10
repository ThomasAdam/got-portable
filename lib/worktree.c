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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include "got_error.h"
#include "got_repository.h"
#include "got_refs.h"
#include "got_worktree.h"

#include "got_worktree_priv.h"
#include "got_path_priv.h"

static const struct got_error *
create_meta_file(const char *gotpath, const char *name, const char *content)
{
	const struct got_error *err = NULL;
	char *path;
	int fd = -1;
	char buf[4];
	ssize_t n;

	if (asprintf(&path, "%s/%s", gotpath, name) == -1) {
		err = got_error(GOT_ERR_NO_MEM);
		path = NULL;
		goto done;
	}

	fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_EXLOCK | O_NOFOLLOW,
	    GOT_DEFAULT_FILE_MODE);
	if (fd == -1) {
		err = got_error_from_errno();
		goto done;
	}

	/* The file should be empty. */
	n = read(fd, buf, sizeof(buf));
	if (n != 0) {
		err = (n == -1 ? got_error_from_errno() :
		    got_error(GOT_ERR_WORKTREE_EXISTS));
		goto done;
	}

	if (content) {
		int len = dprintf(fd, "%s\n", content);
		if (len != strlen(content) + 1) {
			err = got_error_from_errno();
			goto done;
		}
	}

done:
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno();
	free(path);
	return err;
}

const struct got_error *
got_worktree_init(const char *path, struct got_reference *head_ref,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *abspath = NULL;
	char *normpath = NULL;
	char *gotpath = NULL;
	char *refstr = NULL;
	char *path_repos = NULL;
	char *formatstr = NULL;

	if (got_path_is_absolute(path)) {
		abspath = strdup(path);
		if (abspath == NULL)
			return got_error(GOT_ERR_NO_MEM);
	} else {
		abspath = got_path_get_absolute(path);
		if (abspath == NULL)
			return got_error(GOT_ERR_BAD_PATH);
	}

	/* Create top-level directory (may already exist). */
	normpath = got_path_normalize(abspath);
	if (normpath == NULL) {
		err = got_error(GOT_ERR_BAD_PATH);
		goto done;
	}
	if (mkdir(normpath, GOT_DEFAULT_DIR_MODE) == -1 && errno != EEXIST) {
		err = got_error_from_errno();
		goto done;
	}

	/* Create .got directory (may already exist). */
	if (asprintf(&gotpath, "%s/%s", normpath, GOT_WORKTREE_GOT_DIR) == -1) {
		err = got_error(GOT_ERR_NO_MEM);
		goto done;
	}
	if (mkdir(gotpath, GOT_DEFAULT_DIR_MODE) == -1 && errno != EEXIST) {
		err = got_error_from_errno();
		goto done;
	}

	/* Create an empty file index. */
	err = create_meta_file(gotpath, GOT_WORKTREE_FILE_INDEX, NULL);
	if (err)
		goto done;

	/* Write the HEAD reference. */
	refstr = got_ref_to_str(head_ref);
	if (refstr == NULL) {
		err = got_error(GOT_ERR_NO_MEM);
		goto done;
	}
	err = create_meta_file(gotpath, GOT_REF_HEAD, refstr);
	if (err)
		goto done;

	/* Store path to repository. */
	path_repos = got_repo_get_path(repo);
	if (path_repos == NULL) {
		err = got_error(GOT_ERR_NO_MEM);
		goto done;
	}
	err = create_meta_file(gotpath, GOT_WORKTREE_REPOSITORY, path_repos);
	if (err)
		goto done;

	/* Stamp repository with format file. */
	if (asprintf(&formatstr, "%d", GOT_WORKTREE_FORMAT_VERSION) == -1) {
		err = got_error(GOT_ERR_NO_MEM);
		goto done;
	}
	err = create_meta_file(gotpath, GOT_WORKTREE_FORMAT, formatstr);
	if (err)
		goto done;

done:
	free(abspath);
	free(normpath);
	free(gotpath);
	free(formatstr);
	free(refstr);
	free(path_repos);
	return err;
}

const struct got_error *
got_worktree_open(struct got_worktree **worktree, const char *path)
{
	return NULL;
}

void
got_worktree_close(struct got_worktree *worktree)
{
}

char *
got_worktree_get_repo_path(struct got_worktree *worktree)
{
	return strdup(worktree->path_repo);
}

struct got_reference *
got_worktree_get_head(struct got_worktree *worktree)
{
	return NULL;
}

const struct got_error *
got_worktree_set_head(struct got_worktree *worktree, struct got_reference *head,
    struct got_repository *repo)
{
	return NULL;
}

const struct got_error *
got_worktree_update_fileindex(struct got_worktree *worktree,
    struct got_repository *repo)
{
	return NULL;
}

const struct got_error *
got_worktree_checkout_files(struct got_worktree *worktree,
    struct got_repository *repo)
{
	return NULL;
}
