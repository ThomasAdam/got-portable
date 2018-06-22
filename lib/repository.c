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

#include <sys/queue.h>
#include <sys/stat.h>

#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <sha1.h>
#include <string.h>
#include <zlib.h>

#include "got_error.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_worktree.h"
#include "got_object.h"

#include "got_lib_path.h"
#include "got_lib_delta.h"
#include "got_lib_zbuf.h"
#include "got_lib_object.h"
#include "got_lib_pack.h"
#include "got_lib_repository.h"
#include "got_lib_worktree.h"
#include "got_lib_object_idset.h"

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

static const struct got_error *
cache_add(struct got_object_cache *cache, struct got_object_id *id, void *item)
{
	const struct got_error *err = NULL;
	struct got_object_cache_entry *ce;
	int nelem;

	nelem = got_object_idset_num_elements(cache->set);
	if (nelem >= cache->size) {
		err = got_object_idset_remove_random((void **)&ce,
		    cache->set);
		if (err)
			return err;
		switch (cache->type) {
		case GOT_OBJECT_CACHE_TYPE_OBJ:
			got_object_close(ce->data.obj);
			break;
		case GOT_OBJECT_CACHE_TYPE_TREE:
			got_object_tree_close(ce->data.tree);
			break;
		case GOT_OBJECT_CACHE_TYPE_COMMIT:
			got_object_commit_close(ce->data.commit);
			break;
		}
		free(ce);
	}

	ce = calloc(1, sizeof(*ce));
	if (ce == NULL)
		return got_error_from_errno();
	memcpy(&ce->id, id, sizeof(ce->id));
	switch (cache->type) {
	case GOT_OBJECT_CACHE_TYPE_OBJ:
		ce->data.obj = (struct got_object *)item;
		break;
	case GOT_OBJECT_CACHE_TYPE_TREE:
		ce->data.tree = (struct got_tree_object *)item;
		break;
	case GOT_OBJECT_CACHE_TYPE_COMMIT:
		ce->data.commit = (struct got_commit_object *)item;
		break;
	}
	err = got_object_idset_add(NULL, cache->set, id, ce);
	if (err) {
		if (err->code == GOT_ERR_OBJ_EXISTS) {
			free(ce);
			err = NULL;
		}
	}

	return err;
}

const struct got_error *
got_repo_cache_object(struct got_repository *repo, struct got_object_id *id,
    struct got_object *obj)
{
	const struct got_error *err = NULL;

	err = cache_add(&repo->objcache, id, obj);
	if (err)
		return err;

	obj->refcnt++;
	return NULL;
}

struct got_object *
got_repo_get_cached_object(struct got_repository *repo,
    struct got_object_id *id)
{
	struct got_object_cache_entry *ce;

	ce = got_object_idset_get(repo->objcache.set, id);
	if (ce) {
		repo->objcache.cache_hit++;
		return ce->data.obj;
	}

	repo->objcache.cache_miss++;
	return NULL;
}

const struct got_error *
got_repo_cache_tree(struct got_repository *repo, struct got_object_id *id,
    struct got_tree_object *tree)
{
	const struct got_error *err = NULL;

	err = cache_add(&repo->treecache, id, tree);
	if (err)
		return err;

	tree->refcnt++;
	return NULL;
}

struct got_tree_object *
got_repo_get_cached_tree(struct got_repository *repo,
    struct got_object_id *id)
{
	struct got_object_cache_entry *ce;

	ce = got_object_idset_get(repo->treecache.set, id);
	if (ce) {
		repo->treecache.cache_hit++;
		return ce->data.tree;
	}

	repo->treecache.cache_miss++;
	return NULL;
}

const struct got_error *
got_repo_cache_commit(struct got_repository *repo, struct got_object_id *id,
    struct got_commit_object *commit)
{
	const struct got_error *err = NULL;

	err = cache_add(&repo->commitcache, id, commit);
	if (err)
		return err;

	commit->refcnt++;
	return NULL;
}

struct got_commit_object *
got_repo_get_cached_commit(struct got_repository *repo,
    struct got_object_id *id)
{
	struct got_object_cache_entry *ce;

	ce = got_object_idset_get(repo->commitcache.set, id);
	if (ce) {
		repo->commitcache.cache_hit++;
		return ce->data.commit;
	}

	repo->commitcache.cache_miss++;
	return NULL;
}

const struct got_error *
got_repo_open(struct got_repository **ret, const char *path)
{
	struct got_repository *repo = NULL;
	const struct got_error *err = NULL;
	char *abspath;

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

	repo->objcache.set = got_object_idset_alloc();
	if (repo->objcache.set == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	repo->objcache.type = GOT_OBJECT_CACHE_TYPE_OBJ;
	repo->objcache.size = GOT_OBJECT_CACHE_SIZE_OBJ;

	repo->treecache.set = got_object_idset_alloc();
	if (repo->treecache.set == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	repo->treecache.type = GOT_OBJECT_CACHE_TYPE_TREE;
	repo->treecache.size = GOT_OBJECT_CACHE_SIZE_TREE;

	repo->commitcache.set = got_object_idset_alloc();
	if (repo->commitcache.set == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	repo->commitcache.type = GOT_OBJECT_CACHE_TYPE_COMMIT;
	repo->commitcache.size = GOT_OBJECT_CACHE_SIZE_COMMIT;

	repo->path = got_path_normalize(abspath);
	if (repo->path == NULL) {
		err = got_error(GOT_ERR_BAD_PATH);
		goto done;
	}

	repo->path_git_dir = strdup(repo->path);
	if (repo->path_git_dir == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	if (!is_git_repo(repo)) {
		free(repo->path_git_dir);
		if (asprintf(&repo->path_git_dir, "%s/%s", repo->path,
		    GOT_GIT_DIR) == -1) {
			err = got_error_from_errno();
			goto done;
		}
		if (!is_git_repo(repo)) {
			struct got_worktree *worktree;
			if (got_worktree_open(&worktree, repo->path) == NULL) {
				free(repo->path_git_dir);
				repo->path_git_dir =
				    strdup(worktree->repo_path);
				if (repo->path_git_dir == NULL) {
					err = got_error_from_errno();
					goto done;
				}
				if (!is_git_repo(repo)) {
					free(repo->path_git_dir);
					if (asprintf(&repo->path_git_dir,
					    "%s/%s", worktree->repo_path,
					    GOT_GIT_DIR) == -1) {
						err = got_error_from_errno();
						goto done;
					}
				}
				got_worktree_close(worktree);
			}
		}
		if (!is_git_repo(repo)) {
			err = got_error(GOT_ERR_NOT_GIT_REPO);
			goto done;
		}
	}
		
	*ret = repo;
done:
	if (err)
		got_repo_close(repo);
	free(abspath);
	return err;
}

static void
print_cache_stats(struct got_object_cache *cache, const char *name)
{
#if 0
	fprintf(stderr, "%s cache: %d elements, %d hits, %d missed\n",
	    name, got_object_idset_num_elements(cache->set), cache->cache_hit,
	    cache->cache_miss);
#endif
}

void
got_repo_close(struct got_repository *repo)
{
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
	print_cache_stats(&repo->objcache, "object");
	print_cache_stats(&repo->treecache, "tree");
	print_cache_stats(&repo->commitcache, "commit");
	if (repo->objcache.set)
		got_object_idset_free(repo->objcache.set);
	if (repo->treecache.set)
		got_object_idset_free(repo->treecache.set);
	if (repo->commitcache.set)
		got_object_idset_free(repo->commitcache.set);
	free(repo);
}
