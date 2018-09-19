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
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syslimits.h>

#include <fcntl.h>
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

#include "got_error.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_worktree.h"
#include "got_object.h"

#include "got_lib_path.h"
#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_pack.h"
#include "got_lib_privsep.h"
#include "got_lib_worktree.h"
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

/* Other files and directories inside the git directory. */
#define GOT_FETCH_HEAD_FILE	"FETCH_HEAD"
#define GOT_ORIG_HEAD_FILE	"ORIG_HEAD"
#define GOT_OBJECTS_PACK_DIR	"objects/pack"

char *
got_repo_get_path(struct got_repository *repo)
{
	return strdup(repo->path);
}

char *
got_repo_get_path_git_dir(struct got_repository *repo)
{
	return strdup(repo->path_git_dir);
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

static char *
get_path_head(struct got_repository *repo)
{
	return get_path_git_child(repo, GOT_HEAD_FILE);
}

static int
is_git_repo(struct got_repository *repo)
{
	char *path_git = got_repo_get_path_git_dir(repo);
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
	if (got_ref_open(&head_ref, repo, GOT_REF_HEAD) != NULL)
		goto done;
	got_ref_close(head_ref);

	ret = 1;
done:
	free(path_git);
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
	if (err)
		return err;
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
	if (err)
		return err;
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
	if (err)
		return err;
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
open_repo(struct got_repository *repo, const char *path)
{
	const struct got_error *err = NULL;
	struct got_worktree *worktree = NULL;

	/* bare git repository? */
	repo->path_git_dir = strdup(path);
	if (repo->path_git_dir == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	if (is_git_repo(repo)) {
		repo->path = strdup(repo->path_git_dir);
		if (repo->path == NULL) {
			err = got_error_from_errno();
			goto done;
		}
		return NULL;
	}

	/* git repository with working tree? */
	free(repo->path_git_dir);
	if (asprintf(&repo->path_git_dir, "%s/%s", path, GOT_GIT_DIR) == -1) {
		err = got_error_from_errno();
		goto done;
	}
	if (is_git_repo(repo)) {
		repo->path = strdup(path);
		if (repo->path == NULL) {
			err = got_error_from_errno();
			goto done;
		}
		return NULL;
	}

	/* got work tree checked out from bare git repository? */
	free(repo->path_git_dir);
	repo->path_git_dir = NULL;
	err = got_worktree_open(&worktree, path);
	if (err) {
		if (err->code == GOT_ERR_ERRNO && errno == ENOENT)
			err = got_error(GOT_ERR_NOT_GIT_REPO);
		goto done;
	}
	repo->path_git_dir = strdup(worktree->repo_path);
	if (repo->path_git_dir == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	/* got work tree checked out from git repository with working tree? */
	if (!is_git_repo(repo)) {
		free(repo->path_git_dir);
		if (asprintf(&repo->path_git_dir, "%s/%s", worktree->repo_path,
		    GOT_GIT_DIR) == -1) {
			err = got_error_from_errno();
			repo->path_git_dir = NULL;
			goto done;
		}
		if (!is_git_repo(repo)) {
			err = got_error(GOT_ERR_NOT_GIT_REPO);
			goto done;
		}
		repo->path = strdup(worktree->repo_path);
		if (repo->path == NULL) {
			err = got_error_from_errno();
			goto done;
		}
	} else {
		repo->path = strdup(repo->path_git_dir);
		if (repo->path == NULL) {
			err = got_error_from_errno();
			goto done;
		}
	}
done:
	if (worktree)
		got_worktree_close(worktree);
	return err;
}

const struct got_error *
got_repo_open(struct got_repository **repop, const char *path)
{
	struct got_repository *repo = NULL;
	const struct got_error *err = NULL;
	char *abspath, *normpath = NULL;
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
		err = got_error_from_errno();
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

	normpath = got_path_normalize(abspath);
	if (normpath == NULL) {
		err = got_error(GOT_ERR_BAD_PATH);
		goto done;
	}

	path = normpath;
	do {
		err = open_repo(repo, path);
		if (err == NULL)
			break;
		if (err->code != GOT_ERR_NOT_GIT_REPO)
			break;
		if (path[0] == '/' && path[1] == '\0') {
			if (tried_root) {
				err = got_error(GOT_ERR_NOT_GIT_REPO);
				break;
			}
			tried_root = 1;
		}
		path = dirname(path);
		if (path == NULL)
			err = got_error_from_errno();
	} while (path);
done:
	if (err)
		got_repo_close(repo);
	else
		*repop = repo;
	free(abspath);
	free(normpath);
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
		close(repo->privsep_children[i].imsg_fd);
	}
	free(repo);

	return err;
}

const struct got_error *
got_repo_map_path(char **in_repo_path, struct got_repository *repo,
    const char *input_path)
{
	const struct got_error *err = NULL;
	char *repo_abspath = NULL, *cwd = NULL;
	struct stat sb;
	size_t repolen, cwdlen, len;
	char *canonpath, *path;

	*in_repo_path = NULL;

	cwd = getcwd(NULL, 0);
	if (cwd == NULL)
		return got_error_from_errno();

	canonpath = strdup(input_path);
	if (canonpath == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	err = got_canonpath(input_path, canonpath, strlen(canonpath) + 1);
	if (err)
		goto done;

	repo_abspath = got_repo_get_path(repo);
	if (repo_abspath == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	/* TODO: Call "get in-repository path of work-tree node" API. */

	if (lstat(canonpath, &sb) != 0) {
		if (errno != ENOENT) {
			err = got_error_from_errno();
			goto done;
		}
		/*
		 * Path is not on disk.
		 * Assume it is already relative to repository root.
		 */
		path = strdup(canonpath);
	} else {
		int is_repo_child = 0, is_cwd_child = 0;

		path = realpath(canonpath, NULL);
		if (path == NULL) {
			err = got_error_from_errno();
			goto done;
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
				err = got_error_from_errno();
				goto done;
			}
		} else if (is_repo_child && is_cwd_child) {
			char *child;
			/* TODO: Is path inside a got worktree? */
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
			/* TODO: Is path inside a got worktree? */
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
			err = got_error_from_errno();
			goto done;
		}
		free(path);
		path = abspath;
	}

done:
	free(repo_abspath);
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
		memmove(&repo->packidx_cache[1], &repo->packidx_cache[0],
		    sizeof(repo->packidx_cache) -
		    sizeof(repo->packidx_cache[0]));
		i = 0;
	}

	repo->packidx_cache[i] = packidx;
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
		return got_error_from_errno();

	packdir = opendir(path_packdir);
	if (packdir == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	while ((dent = readdir(packdir)) != NULL) {
		if (!is_packidx_filename(dent->d_name, dent->d_namlen))
			continue;

		if (asprintf(&path_packidx, "%s/%s", path_packdir,
		    dent->d_name) == -1) {
			err = got_error_from_errno();
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

	err = got_error(GOT_ERR_NO_OBJ);
done:
	free(path_packdir);
	if (packdir && closedir(packdir) != 0 && err == 0)
		err = got_error_from_errno();
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
		return got_error_from_errno();
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

	*fd = open(path_packfile, O_RDONLY | O_NOFOLLOW, GOT_DEFAULT_FILE_MODE);
	if (*fd == -1)
		return got_error_from_errno();

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
		err = got_error_from_errno();
		goto done;
	}

	err = open_packfile(&pack->fd, path_packfile, packidx);
	if (err)
		goto done;

	err = got_pack_get_packfile_size(&pack->filesize, path_packfile);
	if (err)
		goto done;

	pack->privsep_child = NULL;

#ifndef GOT_PACK_NO_MMAP
	pack->map = mmap(NULL, pack->filesize, PROT_READ, MAP_PRIVATE,
	    pack->fd, 0);
	if (pack->map == MAP_FAILED)
		pack->map = NULL; /* fall back to read(2) */
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
