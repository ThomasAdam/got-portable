/*
 * Copyright (c) 2018, 2019 Stefan Sperling <stsp@openbsd.org>
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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syslimits.h>

#include <ctype.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <limits.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <sha1.h>
#include <string.h>
#include <zlib.h>
#include <errno.h>
#include <libgen.h>
#include <stdint.h>
#include <imsg.h>
#include <uuid.h>

#include "got_error.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_path.h"
#include "got_cancel.h"
#include "got_worktree.h"
#include "got_object.h"

#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_object_parse.h"
#include "got_lib_object_create.h"
#include "got_lib_pack.h"
#include "got_lib_privsep.h"
#include "got_lib_worktree.h"
#include "got_lib_sha1.h"
#include "got_lib_object_cache.h"
#include "got_lib_repository.h"

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

#define GOT_GIT_DIR	".git"

/* Mandatory files and directories inside the git directory. */
#define GOT_OBJECTS_DIR		"objects"
#define GOT_REFS_DIR		"refs"
#define GOT_HEAD_FILE		"HEAD"
#define GOT_GITCONFIG		"config"

/* Other files and directories inside the git directory. */
#define GOT_FETCH_HEAD_FILE	"FETCH_HEAD"
#define GOT_ORIG_HEAD_FILE	"ORIG_HEAD"
#define GOT_OBJECTS_PACK_DIR	"objects/pack"
#define GOT_PACKED_REFS_FILE	"packed-refs"

const char *
got_repo_get_path(struct got_repository *repo)
{
	return repo->path;
}

const char *
got_repo_get_path_git_dir(struct got_repository *repo)
{
	return repo->path_git_dir;
}

const char *
got_repo_get_gitconfig_author_name(struct got_repository *repo)
{
	return repo->gitconfig_author_name;
}

const char *
got_repo_get_gitconfig_author_email(struct got_repository *repo)
{
	return repo->gitconfig_author_email;
}

const char *
got_repo_get_global_gitconfig_author_name(struct got_repository *repo)
{
	return repo->global_gitconfig_author_name;
}

const char *
got_repo_get_global_gitconfig_author_email(struct got_repository *repo)
{
	return repo->global_gitconfig_author_email;
}

int
got_repo_is_bare(struct got_repository *repo)
{
	return (strcmp(repo->path, repo->path_git_dir) == 0);
}

static char *
get_path_git_child(struct got_repository *repo, const char *basename)
{
	char *path_child;
	
	if (asprintf(&path_child, "%s/%s", repo->path_git_dir,
	    basename) == -1)
		return NULL;

	return path_child;
}

char *
got_repo_get_path_objects(struct got_repository *repo)
{
	return get_path_git_child(repo, GOT_OBJECTS_DIR);
}

char *
got_repo_get_path_objects_pack(struct got_repository *repo)
{
	return get_path_git_child(repo, GOT_OBJECTS_PACK_DIR);
}

char *
got_repo_get_path_refs(struct got_repository *repo)
{
	return get_path_git_child(repo, GOT_REFS_DIR);
}

char *
got_repo_get_path_packed_refs(struct got_repository *repo)
{
	return get_path_git_child(repo, GOT_PACKED_REFS_FILE);
}

static char *
get_path_head(struct got_repository *repo)
{
	return get_path_git_child(repo, GOT_HEAD_FILE);
}

static const struct got_error *
get_path_gitconfig(char **p, struct got_repository *repo)
{
	*p = get_path_git_child(repo, GOT_GITCONFIG);
	if (*p == NULL)
		return got_error_from_errno("asprintf");
	return NULL;
}

static int
is_git_repo(struct got_repository *repo)
{
	const char *path_git = got_repo_get_path_git_dir(repo);
	char *path_objects = got_repo_get_path_objects(repo);
	char *path_refs = got_repo_get_path_refs(repo);
	char *path_head = get_path_head(repo);
	int ret = 0;
	struct stat sb;
	struct got_reference *head_ref;

	if (lstat(path_git, &sb) == -1)
		goto done;
	if (!S_ISDIR(sb.st_mode))
		goto done;

	if (lstat(path_objects, &sb) == -1)
		goto done;
	if (!S_ISDIR(sb.st_mode))
		goto done;

	if (lstat(path_refs, &sb) == -1)
		goto done;
	if (!S_ISDIR(sb.st_mode))
		goto done;

	if (lstat(path_head, &sb) == -1)
		goto done;
	if (!S_ISREG(sb.st_mode))
		goto done;

	/* Check if the HEAD reference can be opened. */
	if (got_ref_open(&head_ref, repo, GOT_REF_HEAD, 0) != NULL)
		goto done;
	got_ref_close(head_ref);

	ret = 1;
done:
	free(path_objects);
	free(path_refs);
	free(path_head);
	return ret;

}

const struct got_error *
got_repo_cache_object(struct got_repository *repo, struct got_object_id *id,
    struct got_object *obj)
{
#ifndef GOT_NO_OBJ_CACHE
	const struct got_error *err = NULL;
	err = got_object_cache_add(&repo->objcache, id, obj);
	if (err) {
		if (err->code == GOT_ERR_OBJ_EXISTS ||
		    err->code == GOT_ERR_OBJ_TOO_LARGE)
			err = NULL;
		return err;
	}
	obj->refcnt++;
#endif
	return NULL;
}

struct got_object *
got_repo_get_cached_object(struct got_repository *repo,
    struct got_object_id *id)
{
	return (struct got_object *)got_object_cache_get(&repo->objcache, id);
}

const struct got_error *
got_repo_cache_tree(struct got_repository *repo, struct got_object_id *id,
    struct got_tree_object *tree)
{
#ifndef GOT_NO_OBJ_CACHE
	const struct got_error *err = NULL;
	err = got_object_cache_add(&repo->treecache, id, tree);
	if (err) {
		if (err->code == GOT_ERR_OBJ_EXISTS ||
		    err->code == GOT_ERR_OBJ_TOO_LARGE)
			err = NULL;
		return err;
	}
	tree->refcnt++;
#endif
	return NULL;
}

struct got_tree_object *
got_repo_get_cached_tree(struct got_repository *repo,
    struct got_object_id *id)
{
	return (struct got_tree_object *)got_object_cache_get(
	    &repo->treecache, id);
}

const struct got_error *
got_repo_cache_commit(struct got_repository *repo, struct got_object_id *id,
    struct got_commit_object *commit)
{
#ifndef GOT_NO_OBJ_CACHE
	const struct got_error *err = NULL;
	err = got_object_cache_add(&repo->commitcache, id, commit);
	if (err) {
		if (err->code == GOT_ERR_OBJ_EXISTS ||
		    err->code == GOT_ERR_OBJ_TOO_LARGE)
			err = NULL;
		return err;
	}
	commit->refcnt++;
#endif
	return NULL;
}

struct got_commit_object *
got_repo_get_cached_commit(struct got_repository *repo,
    struct got_object_id *id)
{
	return (struct got_commit_object *)got_object_cache_get(
	    &repo->commitcache, id);
}

const struct got_error *
got_repo_cache_tag(struct got_repository *repo, struct got_object_id *id,
    struct got_tag_object *tag)
{
#ifndef GOT_NO_OBJ_CACHE
	const struct got_error *err = NULL;
	err = got_object_cache_add(&repo->tagcache, id, tag);
	if (err) {
		if (err->code == GOT_ERR_OBJ_EXISTS ||
		    err->code == GOT_ERR_OBJ_TOO_LARGE)
			err = NULL;
		return err;
	}
	tag->refcnt++;
#endif
	return NULL;
}

struct got_tag_object *
got_repo_get_cached_tag(struct got_repository *repo, struct got_object_id *id)
{
	return (struct got_tag_object *)got_object_cache_get(
	    &repo->tagcache, id);
}

const struct got_error *
open_repo(struct got_repository *repo, const char *path)
{
	const struct got_error *err = NULL;

	/* bare git repository? */
	repo->path_git_dir = strdup(path);
	if (repo->path_git_dir == NULL)
		return got_error_from_errno("strdup");
	if (is_git_repo(repo)) {
		repo->path = strdup(repo->path_git_dir);
		if (repo->path == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
		return NULL;
	}

	/* git repository with working tree? */
	free(repo->path_git_dir);
	repo->path_git_dir = NULL;
	if (asprintf(&repo->path_git_dir, "%s/%s", path, GOT_GIT_DIR) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	if (is_git_repo(repo)) {
		repo->path = strdup(path);
		if (repo->path == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
		return NULL;
	}

	err = got_error(GOT_ERR_NOT_GIT_REPO);
done:
	if (err) {
		free(repo->path);
		repo->path = NULL;
		free(repo->path_git_dir);
		repo->path_git_dir = NULL;
	}
	return err;
}

static const struct got_error *
parse_gitconfig_file(int *gitconfig_repository_format_version,
    char **gitconfig_author_name, char **gitconfig_author_email,
    const char *gitconfig_path)
{
	const struct got_error *err = NULL, *child_err = NULL;
	int fd = -1;
	int imsg_fds[2] = { -1, -1 };
	pid_t pid;
	struct imsgbuf *ibuf;

	*gitconfig_repository_format_version = 0;
	*gitconfig_author_name = NULL;
	*gitconfig_author_email = NULL;

	fd = open(gitconfig_path, O_RDONLY);
	if (fd == -1) {
		if (errno == ENOENT)
			return NULL;
		return got_error_from_errno2("open", gitconfig_path);
	}

	ibuf = calloc(1, sizeof(*ibuf));
	if (ibuf == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_fds) == -1) {
		err = got_error_from_errno("socketpair");
		goto done;
	}

	pid = fork();
	if (pid == -1) {
		err = got_error_from_errno("fork");
		goto done;
	} else if (pid == 0) {
		got_privsep_exec_child(imsg_fds, GOT_PATH_PROG_READ_GITCONFIG,
		    gitconfig_path);
		/* not reached */
	}

	if (close(imsg_fds[1]) == -1) {
		err = got_error_from_errno("close");
		goto done;
	}
	imsg_fds[1] = -1;
	imsg_init(ibuf, imsg_fds[0]);

	err = got_privsep_send_gitconfig_parse_req(ibuf, fd);
	if (err)
		goto done;
	fd = -1;

	err = got_privsep_send_gitconfig_repository_format_version_req(ibuf);
	if (err)
		goto done;

	err = got_privsep_recv_gitconfig_int(
	    gitconfig_repository_format_version, ibuf);
	if (err)
		goto done;

	err = got_privsep_send_gitconfig_author_name_req(ibuf);
	if (err)
		goto done;

	err = got_privsep_recv_gitconfig_str(gitconfig_author_name, ibuf);
	if (err)
		goto done;

	err = got_privsep_send_gitconfig_author_email_req(ibuf);
	if (err)
		goto done;

	err = got_privsep_recv_gitconfig_str(gitconfig_author_email, ibuf);
	if (err)
		goto done;

	imsg_clear(ibuf);
	err = got_privsep_send_stop(imsg_fds[0]);
	child_err = got_privsep_wait_for_child(pid);
	if (child_err && err == NULL)
		err = child_err;
done:
	if (imsg_fds[0] != -1 && close(imsg_fds[0]) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (imsg_fds[1] != -1 && close(imsg_fds[1]) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno2("close", gitconfig_path);
	free(ibuf);
	return err;
}

static const struct got_error *
read_gitconfig(struct got_repository *repo, const char *global_gitconfig_path)
{
	const struct got_error *err = NULL;
	char *repo_gitconfig_path = NULL;

	if (global_gitconfig_path) {
		/* Read settings from ~/.gitconfig. */
		int dummy_repo_version;
		err = parse_gitconfig_file(&dummy_repo_version,
		    &repo->global_gitconfig_author_name,
		    &repo->global_gitconfig_author_email,
		    global_gitconfig_path);
		if (err)
			return err;
	}

	/* Read repository's .git/config file. */
	err = get_path_gitconfig(&repo_gitconfig_path, repo);
	if (err)
		return err;

	err = parse_gitconfig_file(&repo->gitconfig_repository_format_version,
	    &repo->gitconfig_author_name, &repo->gitconfig_author_email,
	    repo_gitconfig_path);
	if (err)
		goto done;
done:
	free(repo_gitconfig_path);
	return err;
}

const struct got_error *
got_repo_open(struct got_repository **repop, const char *path,
    const char *global_gitconfig_path)
{
	struct got_repository *repo = NULL;
	const struct got_error *err = NULL;
	char *abspath;
	int i, tried_root = 0;

	*repop = NULL;

	if (got_path_is_absolute(path))
		abspath = strdup(path);
	else
		abspath = got_path_get_absolute(path);
	if (abspath == NULL)
		return got_error(GOT_ERR_BAD_PATH);

	repo = calloc(1, sizeof(*repo));
	if (repo == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}

	for (i = 0; i < nitems(repo->privsep_children); i++) {
		memset(&repo->privsep_children[i], 0,
		    sizeof(repo->privsep_children[0]));
		repo->privsep_children[i].imsg_fd = -1;
	}

	err = got_object_cache_init(&repo->objcache,
	    GOT_OBJECT_CACHE_TYPE_OBJ);
	if (err)
		goto done;
	err = got_object_cache_init(&repo->treecache,
	    GOT_OBJECT_CACHE_TYPE_TREE);
	if (err)
		goto done;
	err = got_object_cache_init(&repo->commitcache,
	    GOT_OBJECT_CACHE_TYPE_COMMIT);
	if (err)
		goto done;
	err = got_object_cache_init(&repo->tagcache,
	    GOT_OBJECT_CACHE_TYPE_TAG);
	if (err)
		goto done;

	path = realpath(abspath, NULL);
	if (path == NULL) {
		err = got_error_from_errno2("realpath", abspath);
		goto done;
	}

	do {
		err = open_repo(repo, path);
		if (err == NULL)
			break;
		if (err->code != GOT_ERR_NOT_GIT_REPO)
			break;
		if (path[0] == '/' && path[1] == '\0') {
			if (tried_root) {
				err = got_error(GOT_ERR_NOT_GIT_REPO);
				goto done;
			}
			tried_root = 1;
		}
		path = dirname(path);
		if (path == NULL) {
			err = got_error_from_errno2("dirname", path);
			goto done;
		}
	} while (path);

	err = read_gitconfig(repo, global_gitconfig_path);
	if (err)
		goto done;
	if (repo->gitconfig_repository_format_version != 0)
		err = got_error_path(path, GOT_ERR_GIT_REPO_FORMAT);
done:
	if (err)
		got_repo_close(repo);
	else
		*repop = repo;
	free(abspath);
	return err;
}

const struct got_error *
got_repo_close(struct got_repository *repo)
{
	const struct got_error *err = NULL, *child_err;
	int i;

	for (i = 0; i < nitems(repo->packidx_cache); i++) {
		if (repo->packidx_cache[i] == NULL)
			break;
		got_packidx_close(repo->packidx_cache[i]);
	}

	for (i = 0; i < nitems(repo->packs); i++) {
		if (repo->packs[i].path_packfile == NULL)
			break;
		got_pack_close(&repo->packs[i]);
	}

	free(repo->path);
	free(repo->path_git_dir);

	got_object_cache_close(&repo->objcache);
	got_object_cache_close(&repo->treecache);
	got_object_cache_close(&repo->commitcache);
	got_object_cache_close(&repo->tagcache);

	for (i = 0; i < nitems(repo->privsep_children); i++) {
		if (repo->privsep_children[i].imsg_fd == -1)
			continue;
		imsg_clear(repo->privsep_children[i].ibuf);
		free(repo->privsep_children[i].ibuf);
		err = got_privsep_send_stop(repo->privsep_children[i].imsg_fd);
		child_err = got_privsep_wait_for_child(
		    repo->privsep_children[i].pid);
		if (child_err && err == NULL)
			err = child_err;
		if (close(repo->privsep_children[i].imsg_fd) != 0 &&
		    err == NULL)
			err = got_error_from_errno("close");
	}

	free(repo->gitconfig_author_name);
	free(repo->gitconfig_author_email);
	free(repo);

	return err;
}

const struct got_error *
got_repo_map_path(char **in_repo_path, struct got_repository *repo,
    const char *input_path, int check_disk)
{
	const struct got_error *err = NULL;
	const char *repo_abspath = NULL;
	size_t repolen, cwdlen, len;
	char *cwd, *canonpath, *path = NULL;

	*in_repo_path = NULL;

	cwd = getcwd(NULL, 0);
	if (cwd == NULL)
		return got_error_from_errno("getcwd");

	canonpath = strdup(input_path);
	if (canonpath == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}
	err = got_canonpath(input_path, canonpath, strlen(canonpath) + 1);
	if (err)
		goto done;

	repo_abspath = got_repo_get_path(repo);

	if (!check_disk || canonpath[0] == '\0') {
		path = strdup(canonpath);
		if (path == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
	} else {
		int is_repo_child = 0, is_cwd_child = 0;

		path = realpath(canonpath, NULL);
		if (path == NULL) {
			if (errno != ENOENT) {
				err = got_error_from_errno2("realpath",
				    canonpath);
				goto done;
			}
			/*
			 * Path is not on disk.
			 * Assume it is already relative to repository root.
			 */
			path = strdup(canonpath);
			if (path == NULL) {
				err = got_error_from_errno("strdup");
				goto done;
			}
		}

		repolen = strlen(repo_abspath);
		cwdlen = strlen(cwd);
		len = strlen(path);

		if (len > repolen && strncmp(path, repo_abspath, repolen) == 0)
			is_repo_child = 1;
		if (len > cwdlen && strncmp(path, cwd, cwdlen) == 0)
			is_cwd_child = 1;

		if (strcmp(path, repo_abspath) == 0) {
			free(path);
			path = strdup("");
			if (path == NULL) {
				err = got_error_from_errno("strdup");
				goto done;
			}
		} else if (is_repo_child && is_cwd_child) {
			char *child;
			/* Strip common prefix with repository path. */
			err = got_path_skip_common_ancestor(&child,
			    repo_abspath, path);
			if (err)
				goto done;
			free(path);
			path = child;
		} else if (is_repo_child) {
			/* Matched an on-disk path inside repository. */
			if (got_repo_is_bare(repo)) {
				/*
				 * Matched an on-disk path inside repository
				 * database. Treat as repository-relative.
				 */
			} else {
				char *child;
				/* Strip common prefix with repository path. */
				err = got_path_skip_common_ancestor(&child,
				    repo_abspath, path);
				if (err)
					goto done;
				free(path);
				path = child;
			}
		} else if (is_cwd_child) {
			char *child;
			/* Strip common prefix with cwd. */
			err = got_path_skip_common_ancestor(&child, cwd,
			    path);
			if (err)
				goto done;
			free(path);
			path = child;
		} else {
			/*
			 * Matched unrelated on-disk path.
			 * Treat it as repository-relative.
			 */
		}
	}

	/* Make in-repository path absolute */
	if (path[0] != '/') {
		char *abspath;
		if (asprintf(&abspath, "/%s", path) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
		free(path);
		path = abspath;
	}

done:
	free(cwd);
	free(canonpath);
	if (err)
		free(path);
	else
		*in_repo_path = path;
	return err;
}

const struct got_error *
got_repo_cache_packidx(struct got_repository *repo, struct got_packidx *packidx)
{
	const struct got_error *err = NULL;
	int i;

	for (i = 0; i < nitems(repo->packidx_cache); i++) {
		if (repo->packidx_cache[i] == NULL)
			break;
	}
	if (i == nitems(repo->packidx_cache)) {
		err = got_packidx_close(repo->packidx_cache[i - 1]);
		if (err)
			return err;
	}

	/*
	 * Insert the new pack index at the front so it will
	 * be searched first in the future.
	 */
	memmove(&repo->packidx_cache[1], &repo->packidx_cache[0],
	    sizeof(repo->packidx_cache) -
	    sizeof(repo->packidx_cache[0]));
	repo->packidx_cache[0] = packidx;

	return NULL;
}

static int
is_packidx_filename(const char *name, size_t len)
{
	if (len != GOT_PACKIDX_NAMELEN)
		return 0;

	if (strncmp(name, GOT_PACK_PREFIX, strlen(GOT_PACK_PREFIX)) != 0)
		return 0;

	if (strcmp(name + strlen(GOT_PACK_PREFIX) +
	    SHA1_DIGEST_STRING_LENGTH - 1, GOT_PACKIDX_SUFFIX) != 0)
		return 0;

	return 1;
}

const struct got_error *
got_repo_search_packidx(struct got_packidx **packidx, int *idx,
    struct got_repository *repo, struct got_object_id *id)
{
	const struct got_error *err;
	char *path_packdir;
	DIR *packdir;
	struct dirent *dent;
	char *path_packidx;
	int i;

	/* Search pack index cache. */
	for (i = 0; i < nitems(repo->packidx_cache); i++) {
		if (repo->packidx_cache[i] == NULL)
			break;
		*idx = got_packidx_get_object_idx(repo->packidx_cache[i], id);
		if (*idx != -1) {
			*packidx = repo->packidx_cache[i];
			return NULL;
		}
	}
	/* No luck. Search the filesystem. */

	path_packdir = got_repo_get_path_objects_pack(repo);
	if (path_packdir == NULL)
		return got_error_from_errno("got_repo_get_path_objects_pack");

	packdir = opendir(path_packdir);
	if (packdir == NULL) {
		if (errno == ENOENT)
			err = got_error_no_obj(id);
		else
			err = got_error_from_errno2("opendir", path_packdir);
		goto done;
	}

	while ((dent = readdir(packdir)) != NULL) {
		if (!is_packidx_filename(dent->d_name, dent->d_namlen))
			continue;

		if (asprintf(&path_packidx, "%s/%s", path_packdir,
		    dent->d_name) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}

		err = got_packidx_open(packidx, path_packidx, 0);
		free(path_packidx);
		if (err)
			goto done;

		*idx = got_packidx_get_object_idx(*packidx, id);
		if (*idx != -1) {
			err = NULL; /* found the object */
			err = got_repo_cache_packidx(repo, *packidx);
			goto done;
		}

		err = got_packidx_close(*packidx);
		*packidx = NULL;
		if (err)
			goto done;
	}

	err = got_error_no_obj(id);
done:
	free(path_packdir);
	if (packdir && closedir(packdir) != 0 && err == NULL)
		err = got_error_from_errno("closedir");
	return err;
}

static const struct got_error *
read_packfile_hdr(int fd, struct got_packidx *packidx)
{
	const struct got_error *err = NULL;
	uint32_t totobj = betoh32(packidx->hdr.fanout_table[0xff]);
	struct got_packfile_hdr hdr;
	ssize_t n;

	n = read(fd, &hdr, sizeof(hdr));
	if (n < 0)
		return got_error_from_errno("read");
	if (n != sizeof(hdr))
		return got_error(GOT_ERR_BAD_PACKFILE);

	if (betoh32(hdr.signature) != GOT_PACKFILE_SIGNATURE ||
	    betoh32(hdr.version) != GOT_PACKFILE_VERSION ||
	    betoh32(hdr.nobjects) != totobj)
		err = got_error(GOT_ERR_BAD_PACKFILE);

	return err;
}

static const struct got_error *
open_packfile(int *fd, const char *path_packfile, struct got_packidx *packidx)
{
	const struct got_error *err = NULL;

	*fd = open(path_packfile, O_RDONLY | O_NOFOLLOW);
	if (*fd == -1)
		return got_error_from_errno2("open", path_packfile);

	if (packidx) {
		err = read_packfile_hdr(*fd, packidx);
		if (err) {
			close(*fd);
			*fd = -1;
		}
	}

	return err;
}

const struct got_error *
got_repo_cache_pack(struct got_pack **packp, struct got_repository *repo,
    const char *path_packfile, struct got_packidx *packidx)
{
	const struct got_error *err = NULL;
	struct got_pack *pack = NULL;
	struct stat sb;
	int i;

	if (packp)
		*packp = NULL;

	for (i = 0; i < nitems(repo->packs); i++) {
		pack = &repo->packs[i];
		if (pack->path_packfile == NULL)
			break;
		if (strcmp(pack->path_packfile, path_packfile) == 0)
			return NULL;
	}

	if (i == nitems(repo->packs) - 1) {
		err = got_pack_close(&repo->packs[i - 1]);
		if (err)
			return err;
		memmove(&repo->packs[1], &repo->packs[0],
		    sizeof(repo->packs) - sizeof(repo->packs[0]));
		i = 0;
	}

	pack = &repo->packs[i];

	pack->path_packfile = strdup(path_packfile);
	if (pack->path_packfile == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

	err = open_packfile(&pack->fd, path_packfile, packidx);
	if (err)
		goto done;

	if (fstat(pack->fd, &sb) != 0) {
		err = got_error_from_errno("fstat");
		goto done;
	}
	pack->filesize = sb.st_size;

	pack->privsep_child = NULL;

#ifndef GOT_PACK_NO_MMAP
	pack->map = mmap(NULL, pack->filesize, PROT_READ, MAP_PRIVATE,
	    pack->fd, 0);
	if (pack->map == MAP_FAILED) {
		if (errno != ENOMEM) {
			err = got_error_from_errno("mmap");
			goto done;
		}
		pack->map = NULL; /* fall back to read(2) */
	}
#endif
done:
	if (err) {
		if (pack) {
			free(pack->path_packfile);
			memset(pack, 0, sizeof(*pack));
		}
	} else if (packp)
		*packp = pack;
	return err;
}

struct got_pack *
got_repo_get_cached_pack(struct got_repository *repo, const char *path_packfile)
{
	struct got_pack *pack = NULL;
	int i;

	for (i = 0; i < nitems(repo->packs); i++) {
		pack = &repo->packs[i];
		if (pack->path_packfile == NULL)
			break;
		if (strcmp(pack->path_packfile, path_packfile) == 0)
			return pack;
	}

	return NULL;
}

const struct got_error *
got_repo_init(const char *repo_path)
{
	const struct got_error *err = NULL;
	const char *dirnames[] = {
		GOT_OBJECTS_DIR,
		GOT_OBJECTS_PACK_DIR,
		GOT_REFS_DIR,
	};
	const char *description_str = "Unnamed repository; "
	    "edit this file 'description' to name the repository.";
	const char *headref_str = "ref: refs/heads/master";
	const char *gitconfig_str = "[core]\n"
	    "\trepositoryformatversion = 0\n"
	    "\tfilemode = true\n"
	    "\tbare = true\n";
	char *path;
	int i;

	if (!got_path_dir_is_empty(repo_path))
		return got_error(GOT_ERR_DIR_NOT_EMPTY);

	for (i = 0; i < nitems(dirnames); i++) {
		if (asprintf(&path, "%s/%s", repo_path, dirnames[i]) == -1) {
			return got_error_from_errno("asprintf");
		}
		err = got_path_mkdir(path);
		free(path);
		if (err)
			return err;
	}

	if (asprintf(&path, "%s/%s", repo_path, "description") == -1)
		return got_error_from_errno("asprintf");
	err = got_path_create_file(path, description_str);
	free(path);
	if (err)
		return err;

	if (asprintf(&path, "%s/%s", repo_path, GOT_HEAD_FILE) == -1)
		return got_error_from_errno("asprintf");
	err = got_path_create_file(path, headref_str);
	free(path);
	if (err)
		return err;

	if (asprintf(&path, "%s/%s", repo_path, "config") == -1)
		return got_error_from_errno("asprintf");
	err = got_path_create_file(path, gitconfig_str);
	free(path);
	if (err)
		return err;

	return NULL;
}

static const struct got_error *
match_packed_object(struct got_object_id **unique_id,
    struct got_repository *repo, const char *id_str_prefix, int obj_type)
{
	const struct got_error *err = NULL;
	char *path_packdir;
	DIR *packdir;
	struct dirent *dent;
	char *path_packidx;
	struct got_object_id_queue matched_ids;

	SIMPLEQ_INIT(&matched_ids);

	path_packdir = got_repo_get_path_objects_pack(repo);
	if (path_packdir == NULL)
		return got_error_from_errno("got_repo_get_path_objects_pack");

	packdir = opendir(path_packdir);
	if (packdir == NULL) {
		if (errno != ENOENT)
			err = got_error_from_errno2("opendir", path_packdir);
		goto done;
	}

	while ((dent = readdir(packdir)) != NULL) {
		struct got_packidx *packidx;
		struct got_object_qid *qid;


		if (!is_packidx_filename(dent->d_name, dent->d_namlen))
			continue;

		if (asprintf(&path_packidx, "%s/%s", path_packdir,
		    dent->d_name) == -1) {
			err = got_error_from_errno("asprintf");
			break;
		}

		err = got_packidx_open(&packidx, path_packidx, 0);
		free(path_packidx);
		if (err)
			break;

		err = got_packidx_match_id_str_prefix(&matched_ids,
		    packidx, id_str_prefix);
		if (err) {
			got_packidx_close(packidx);
			break;
		}
		err = got_packidx_close(packidx);
		if (err)
			break;

		SIMPLEQ_FOREACH(qid, &matched_ids, entry) {
			if (obj_type != GOT_OBJ_TYPE_ANY) {
				int matched_type;
				err = got_object_get_type(&matched_type, repo,
				    qid->id);
				if (err)
					goto done;
				if (matched_type != obj_type)
					continue;
			}
			if (*unique_id == NULL) {
				*unique_id = got_object_id_dup(qid->id);
				if (*unique_id == NULL) {
					err = got_error_from_errno("malloc");
					goto done;
				}
			} else {
				err = got_error(GOT_ERR_AMBIGUOUS_ID);
				goto done;
			}
		}
	}
done:
	got_object_id_queue_free(&matched_ids);
	free(path_packdir);
	if (packdir && closedir(packdir) != 0 && err == NULL)
		err = got_error_from_errno("closedir");
	if (err) {
		free(*unique_id);
		*unique_id = NULL;
	}
	return err;
}

static const struct got_error *
match_loose_object(struct got_object_id **unique_id, const char *path_objects,
    const char *object_dir, const char *id_str_prefix, int obj_type,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *path;
	DIR *dir = NULL;
	struct dirent *dent;
	struct got_object_id id;

	if (asprintf(&path, "%s/%s", path_objects, object_dir) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	dir = opendir(path);
	if (dir == NULL) {
		if (errno == ENOENT) {
			err = NULL;
			goto done;
		}
		err = got_error_from_errno2("opendir", path);
		goto done;
	}
	while ((dent = readdir(dir)) != NULL) {
		char *id_str;
		int cmp;

		if (strcmp(dent->d_name, ".") == 0 ||
		    strcmp(dent->d_name, "..") == 0)
			continue;

		if (asprintf(&id_str, "%s%s", object_dir, dent->d_name) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}

		if (!got_parse_sha1_digest(id.sha1, id_str))
			continue;

		/*
		 * Directory entries do not necessarily appear in
		 * sorted order, so we must iterate over all of them.
		 */
		cmp = strncmp(id_str, id_str_prefix, strlen(id_str_prefix));
		if (cmp != 0) {
			free(id_str);
			continue;
		}

		if (*unique_id == NULL) {
			if (obj_type != GOT_OBJ_TYPE_ANY) {
				int matched_type;
				err = got_object_get_type(&matched_type, repo,
				    &id);
				if (err)
					goto done;
				if (matched_type != obj_type)
					continue;
			}
			*unique_id = got_object_id_dup(&id);
			if (*unique_id == NULL) {
				err = got_error_from_errno("got_object_id_dup");
				free(id_str);
				goto done;
			}
		} else {
			err = got_error(GOT_ERR_AMBIGUOUS_ID);
			free(id_str);
			goto done;
		}
	}
done:
	if (dir && closedir(dir) != 0 && err == NULL)
		err = got_error_from_errno("closedir");
	if (err) {
		free(*unique_id);
		*unique_id = NULL;
	}
	free(path);
	return err;
}

const struct got_error *
got_repo_match_object_id_prefix(struct got_object_id **id,
    const char *id_str_prefix, int obj_type, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *path_objects = got_repo_get_path_objects(repo);
	char *object_dir = NULL;
	size_t len;
	int i;

	*id = NULL;

	for (i = 0; i < strlen(id_str_prefix); i++) {
		if (isxdigit((unsigned char)id_str_prefix[i]))
			continue;
		return got_error(GOT_ERR_BAD_OBJ_ID_STR);
	}

	len = strlen(id_str_prefix);
	if (len >= 2) {
		err = match_packed_object(id, repo, id_str_prefix, obj_type);
		if (err)
			goto done;
		object_dir = strndup(id_str_prefix, 2);
		if (object_dir == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
		err = match_loose_object(id, path_objects, object_dir,
		    id_str_prefix, obj_type, repo);
	} else if (len == 1) {
		int i;
		for (i = 0; i < 0xf; i++) {
			if (asprintf(&object_dir, "%s%.1x", id_str_prefix, i)
			    == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}
			err = match_packed_object(id, repo, object_dir,
			    obj_type);
			if (err)
				goto done;
			err = match_loose_object(id, path_objects, object_dir,
			    id_str_prefix, obj_type, repo);
			if (err)
				goto done;
		}
	} else {
		err = got_error(GOT_ERR_BAD_OBJ_ID_STR);
		goto done;
	}
done:
	free(object_dir);
	if (err) {
		free(*id);
		*id = NULL;
	} else if (*id == NULL)
		err = got_error(GOT_ERR_NO_OBJ);

	return err;
}

const struct got_error *
got_repo_object_match_tag(struct got_tag_object **tag, const char *name,
    int obj_type, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;
	struct got_object_id *tag_id;

	SIMPLEQ_INIT(&refs);
	*tag = NULL;

	err = got_ref_list(&refs, repo, "refs/tags", got_ref_cmp_by_name, NULL);
	if (err)
		return err;

	SIMPLEQ_FOREACH(re, &refs, entry) {
		const char *refname;
		refname = got_ref_get_name(re->ref);
		if (got_ref_is_symbolic(re->ref))
			continue;
		refname += strlen("refs/tags/");
		if (strcmp(refname, name) != 0)
			continue;
		err = got_ref_resolve(&tag_id, repo, re->ref);
		if (err)
			break;
		err = got_object_open_as_tag(tag, repo, tag_id);
		free(tag_id);
		if (err)
			break;
		if (obj_type == GOT_OBJ_TYPE_ANY ||
		    got_object_tag_get_object_type(*tag) == obj_type)
			break;
		got_object_tag_close(*tag);
		*tag = NULL;
	}

	got_ref_list_free(&refs);
	if (err == NULL && *tag == NULL)
		err = got_error(GOT_ERR_NO_OBJ);
	return err;
}

static const struct got_error *
alloc_added_blob_tree_entry(struct got_tree_entry **new_te,
    const char *name, mode_t mode, struct got_object_id *blob_id)
{
	const struct got_error *err = NULL;

	 *new_te = NULL;

	*new_te = calloc(1, sizeof(**new_te));
	if (*new_te == NULL)
		return got_error_from_errno("calloc");

	(*new_te)->name = strdup(name);
	if ((*new_te)->name == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

	(*new_te)->mode = S_IFREG | (mode & ((S_IRWXU | S_IRWXG | S_IRWXO)));
	(*new_te)->id = blob_id;
done:
	if (err && *new_te) {
		got_object_tree_entry_close(*new_te);
		*new_te = NULL;
	}
	return err;
}

static const struct got_error *
import_file(struct got_tree_entry **new_te, struct dirent *de,
    const char *path, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_object_id *blob_id = NULL;
	char *filepath;
	struct stat sb;

	if (asprintf(&filepath, "%s%s%s", path,
	    path[0] == '\0' ? "" : "/", de->d_name) == -1)
		return got_error_from_errno("asprintf");

	if (lstat(filepath, &sb) != 0) {
		err = got_error_from_errno2("lstat", path);
		goto done;
	}

	err = got_object_blob_create(&blob_id, filepath, repo);
	if (err)
		goto done;

	err = alloc_added_blob_tree_entry(new_te, de->d_name, sb.st_mode,
	    blob_id);
done:
	free(filepath);
	if (err)
		free(blob_id);
	return err;
}

static const struct got_error *
insert_tree_entry(struct got_tree_entry *new_te,
    struct got_pathlist_head *paths)
{
	const struct got_error *err = NULL;
	struct got_pathlist_entry *new_pe;

	err = got_pathlist_insert(&new_pe, paths, new_te->name, new_te);
	if (err)
		return err;
	if (new_pe == NULL)
		return got_error(GOT_ERR_TREE_DUP_ENTRY);
	return NULL;
}

static const struct got_error *write_tree(struct got_object_id **,
    const char *, struct got_pathlist_head *, struct got_repository *,
    got_repo_import_cb progress_cb, void *progress_arg);

static const struct got_error *
import_subdir(struct got_tree_entry **new_te, struct dirent *de,
    const char *path, struct got_pathlist_head *ignores,
    struct got_repository *repo,
    got_repo_import_cb progress_cb, void *progress_arg)
{
	const struct got_error *err;
	char *subdirpath;

	if (asprintf(&subdirpath, "%s%s%s", path,
	    path[0] == '\0' ? "" : "/", de->d_name) == -1)
		return got_error_from_errno("asprintf");

	(*new_te) = calloc(1, sizeof(**new_te));
	(*new_te)->mode = S_IFDIR;
	(*new_te)->name = strdup(de->d_name);
	if ((*new_te)->name == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

	err = write_tree(&(*new_te)->id, subdirpath, ignores,  repo,
	    progress_cb, progress_arg);
done:
	free(subdirpath);
	if (err) {
		got_object_tree_entry_close(*new_te);
		*new_te = NULL;
	}
	return err;
}

static const struct got_error *
write_tree(struct got_object_id **new_tree_id, const char *path_dir,
    struct got_pathlist_head *ignores, struct got_repository *repo,
    got_repo_import_cb progress_cb, void *progress_arg)
{
	const struct got_error *err = NULL;
	DIR *dir;
	struct dirent *de;
	struct got_tree_entries new_tree_entries;
	struct got_tree_entry *new_te = NULL;
	struct got_pathlist_head paths;
	struct got_pathlist_entry *pe;

	*new_tree_id = NULL;

	TAILQ_INIT(&paths);
	new_tree_entries.nentries = 0;
	SIMPLEQ_INIT(&new_tree_entries.head);

	dir = opendir(path_dir);
	if (dir == NULL) {
		err = got_error_from_errno2("opendir", path_dir);
		goto done;
	}

	while ((de = readdir(dir)) != NULL) {
		int ignore = 0;

		if (strcmp(de->d_name, ".") == 0 ||
		    strcmp(de->d_name, "..") == 0)
			continue;

		TAILQ_FOREACH(pe, ignores, entry) {
			if (fnmatch(pe->path, de->d_name, 0) == 0) {
				ignore = 1;
				break;
			}
		}
		if (ignore)
			continue;
		if (de->d_type == DT_DIR) {
			err = import_subdir(&new_te, de, path_dir,
			    ignores, repo, progress_cb, progress_arg);
			if (err)
				goto done;
		} else if (de->d_type == DT_REG) {
			err = import_file(&new_te, de, path_dir, repo);
			if (err)
				goto done;
		} else
			continue;

		err = insert_tree_entry(new_te, &paths);
		if (err)
			goto done;
	}

	TAILQ_FOREACH(pe, &paths, entry) {
		struct got_tree_entry *te = pe->data;
		char *path;
		new_tree_entries.nentries++;
		SIMPLEQ_INSERT_TAIL(&new_tree_entries.head, te, entry);
		if (!S_ISREG(te->mode))
			continue;
		if (asprintf(&path, "%s/%s", path_dir, pe->path) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
		err = (*progress_cb)(progress_arg, path);
		free(path);
		if (err)
			goto done;
	}

	err = got_object_tree_create(new_tree_id, &new_tree_entries, repo);
done:
	if (dir)
		closedir(dir);
	got_object_tree_entries_close(&new_tree_entries);
	got_pathlist_free(&paths);
	return err;
}

const struct got_error *
got_repo_import(struct got_object_id **new_commit_id, const char *path_dir,
    const char *logmsg, const char *author, struct got_pathlist_head *ignores,
    struct got_repository *repo, got_repo_import_cb progress_cb,
    void *progress_arg)
{
	const struct got_error *err;
	struct got_object_id *new_tree_id;

	err = write_tree(&new_tree_id, path_dir, ignores, repo,
	    progress_cb, progress_arg);
	if (err)
		return err;

	err = got_object_commit_create(new_commit_id, new_tree_id, NULL, 0,
	    author, time(NULL), author, time(NULL), logmsg, repo);
	free(new_tree_id);
	return err;
}
