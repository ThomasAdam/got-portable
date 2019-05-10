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

#define GOT_PACKIDX_CACHE_SIZE	4
#define GOT_PACK_CACHE_SIZE	GOT_PACKIDX_CACHE_SIZE

struct got_repository {
	char *path;
	char *path_git_dir;

	/* The pack index cache speeds up search for packed objects. */
	struct got_packidx *packidx_cache[GOT_PACKIDX_CACHE_SIZE];

	/* Open file handles for pack files. */
	struct got_pack packs[GOT_PACK_CACHE_SIZE];

	/* Handles to child processes for reading loose objects. */
	 struct got_privsep_child privsep_children[5];
#define GOT_REPO_PRIVSEP_CHILD_OBJECT	0
#define GOT_REPO_PRIVSEP_CHILD_COMMIT	1
#define GOT_REPO_PRIVSEP_CHILD_TREE	2
#define GOT_REPO_PRIVSEP_CHILD_BLOB	3
#define GOT_REPO_PRIVSEP_CHILD_TAG	4

	/* Caches for open objects. */
	struct got_object_cache objcache;
	struct got_object_cache treecache;
	struct got_object_cache commitcache;
	struct got_object_cache tagcache;
};

const struct got_error*got_repo_cache_object(struct got_repository *,
    struct got_object_id *, struct got_object *);
struct got_object *got_repo_get_cached_object(struct got_repository *,
    struct got_object_id *);
const struct got_error*got_repo_cache_tree(struct got_repository *,
    struct got_object_id *, struct got_tree_object *);
struct got_tree_object *got_repo_get_cached_tree(struct got_repository *,
    struct got_object_id *);
const struct got_error*got_repo_cache_commit(struct got_repository *,
    struct got_object_id *, struct got_commit_object *);
struct got_commit_object *got_repo_get_cached_commit(struct got_repository *,
    struct got_object_id *);
const struct got_error*got_repo_cache_tag(struct got_repository *,
    struct got_object_id *, struct got_tag_object *);
struct got_tag_object *got_repo_get_cached_tag(struct got_repository *,
    struct got_object_id *);
const struct got_error *got_repo_cache_packidx(struct got_repository *,
    struct got_packidx *);
const struct got_error *got_repo_search_packidx(struct got_packidx **, int *,
    struct got_repository *, struct got_object_id *);
const struct got_error *got_repo_cache_pack(struct got_pack **,
    struct got_repository *, const char *, struct got_packidx *);
