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

#include <assert.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <sha1.h>
#include <string.h>

#include "got_path.h"
#include "got_error.h"
#include "got_refs.h"
#include "got_repository.h"

#define GOT_GIT_DIR	".git"

/* Mandatory files and directories inside the git directory. */
#define GOT_OBJECTS_DIR	"objects"
#define GOT_REFS_DIR	"refs"
#define GOT_HEAD_FILE	"HEAD"

static char *
get_path_git_dir(struct got_repository *repo)
{
	char *path_git;
	
	if (asprintf(&path_git, "%s/%s", repo->path, GOT_GIT_DIR) == -1)
		return NULL;

	return path_git;
}

static char *
get_path_git_child(struct got_repository *repo, const char *basename)
{
	char *path_child;
	
	if (asprintf(&path_child, "%s/%s/%s", repo->path, GOT_GIT_DIR,
	    basename) == -1)
		return NULL;

	return path_child;
}

static char *
get_path_objects(struct got_repository *repo)
{
	return get_path_git_child(repo, GOT_OBJECTS_DIR);
}

static char *
get_path_refs(struct got_repository *repo)
{
	return get_path_git_child(repo, GOT_REFS_DIR);
}

static char *
get_path_head(struct got_repository *repo)
{
	return get_path_git_child(repo, GOT_HEAD_FILE);
}

static int
is_git_repo(struct got_repository *repo)
{
	char *path_git = get_path_git_dir(repo);
	char *path_objects = get_path_objects(repo);
	char *path_refs = get_path_refs(repo);
	char *path_head = get_path_head(repo);
	int ret;

	ret = (path_git != NULL) && (path_objects != NULL) &&
	    (path_refs != NULL) && (path_head != NULL);

	free(path_git);
	free(path_objects);
	free(path_refs);
	free(path_head);
	return ret;

}

const struct got_error *
got_repo_open(struct got_repository **ret, const char *abspath)
{
	struct got_repository *repo;

	if (!got_path_is_absolute(abspath))
		return got_error(GOT_ERR_NOT_ABSPATH);

	repo = calloc(1, sizeof(*repo));
	if (repo == NULL)
		return got_error(GOT_ERR_NO_MEM);

	repo->path = got_path_normalize(abspath);
	if (repo->path == NULL)
		return got_error(GOT_ERR_BAD_PATH);

	if (!is_git_repo(repo))
		return got_error(GOT_ERR_NOT_GIT_REPO);
		
	*ret = repo;
	return NULL;
}

void
got_repo_close(struct got_repository *repo)
{
	free(repo->path);
	free(repo);
}

const char *
got_repo_get_path(struct got_repository *repo)
{
	return repo->path;
}

const struct got_error *
got_repo_get_reference(struct got_reference **ref,
    struct got_repository *repo, const char *refname)
{
	const struct got_error *err = NULL;
	char *path_refs;

	/* Some refs live in the .git directory. */
	if (strcmp(refname, GOT_REF_HEAD) == 0)
		path_refs = get_path_git_dir(repo);
	else
		path_refs = get_path_refs(repo);

	err = got_ref_open(ref, path_refs, refname);
	free(path_refs);
	return err;
}
