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

#define GOT_PACK_CACHE_SIZE	64

struct got_repository {
	char *path;
	char *path_git_dir;
	int gitdir_fd;

	/* The pack index cache speeds up search for packed objects. */
	struct got_packidx *packidx_cache[GOT_PACK_CACHE_SIZE];

	/* Open file handles for pack files. */
	struct got_pack packs[GOT_PACK_CACHE_SIZE];

	/*
	 * The cache size limit may be lower than GOT_PACK_CACHE_SIZE,
	 * depending on resource limits.
	 */
	int pack_cache_size;

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

	/* Settings read from Git configuration files. */
	int gitconfig_repository_format_version;
	char *gitconfig_author_name;
	char *gitconfig_author_email;
	char *global_gitconfig_author_name;
	char *global_gitconfig_author_email;
	int ngitconfig_remotes;
	struct got_remote_repo *gitconfig_remotes;
	char *gitconfig_owner;
	char **extensions;
	int nextensions;

	/* Settings read from got.conf. */
	struct got_gotconfig *gotconfig;
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
const struct got_error *got_repo_search_packidx(struct got_packidx **, int *,
    struct got_repository *, struct got_object_id *);
const struct got_error *got_repo_cache_pack(struct got_pack **,
    struct got_repository *, const char *, struct got_packidx *);
