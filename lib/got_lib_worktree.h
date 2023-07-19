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

struct got_worktree {
	char *root_path;
	const char *meta_dir;
	char *repo_path;
	int root_fd;
	char *path_prefix;
	struct got_object_id *base_commit_id;
	char *head_ref_name;
	uuid_t uuid;

	/*
	 * File descriptor for the lock file, open while a work tree is open.
	 * When a work tree is opened, a shared lock on the lock file is
	 * acquired with flock(2). This shared lock is held until the work
	 * tree is closed, i.e. throughout the lifetime of any operation
	 * which uses a work tree.
	 * Before any modifications are made to the on-disk state of work
	 * tree meta data, tracked files, or directory tree structure, this
	 * shared lock must be upgraded to an exclusive lock.
	 */
	int lockfd;

	/* Absolute path to worktree's got.conf file. */
	char *gotconfig_path;

	/* Settings read from got.conf. */
	struct got_gotconfig *gotconfig;
};

struct got_commitable {
	char *path;
	char *in_repo_path;
	char *ondisk_path;
	unsigned char status;
	unsigned char staged_status;
	struct got_object_id *blob_id;
	struct got_object_id *base_blob_id;
	struct got_object_id *staged_blob_id;
	struct got_object_id *base_commit_id;
	mode_t mode;
	int flags;
#define GOT_COMMITABLE_ADDED 0x01
};

/* Also defined in got_worktree.h */
#ifndef GOT_WORKTREE_GOT_DIR
#define GOT_WORKTREE_GOT_DIR		".got"
#endif
#ifndef GOT_WORKTREE_CVG_DIR
#define GOT_WORKTREE_CVG_DIR		".cvg"
#endif

#define GOT_WORKTREE_FILE_INDEX		"file-index"
#define GOT_WORKTREE_REPOSITORY		"repository"
#define GOT_WORKTREE_PATH_PREFIX	"path-prefix"
#define GOT_WORKTREE_HEAD_REF		"head-ref"
#define GOT_WORKTREE_BASE_COMMIT	"base-commit"
#define GOT_WORKTREE_LOCK		"lock"
#define GOT_WORKTREE_FORMAT		"format"
#define GOT_WORKTREE_UUID		"uuid"
#define GOT_WORKTREE_HISTEDIT_SCRIPT	"histedit-script"

#define GOT_WORKTREE_FORMAT_VERSION	1
#define GOT_WORKTREE_INVALID_COMMIT_ID	GOT_SHA1_STRING_ZERO

#define GOT_WORKTREE_BASE_REF_PREFIX "refs/got/worktree/base"

/* Temporary branch which accumulates commits during a rebase operation. */
#define GOT_WORKTREE_REBASE_TMP_REF_PREFIX "refs/got/worktree/rebase/tmp"

/* Symbolic reference pointing at the name of the new base branch. */
#define GOT_WORKTREE_NEWBASE_REF_PREFIX "refs/got/worktree/rebase/newbase"

/* Symbolic reference pointing at the name of the branch being rebased. */
#define GOT_WORKTREE_REBASE_BRANCH_REF_PREFIX "refs/got/worktree/rebase/branch"

/* Reference pointing at the ID of the current commit being rebased. */
#define GOT_WORKTREE_REBASE_COMMIT_REF_PREFIX "refs/got/worktree/rebase/commit"

/* Temporary branch which accumulates commits during a histedit operation. */
#define GOT_WORKTREE_HISTEDIT_TMP_REF_PREFIX "refs/got/worktree/histedit/tmp"

/* Symbolic reference pointing at the name of the branch being edited. */
#define GOT_WORKTREE_HISTEDIT_BRANCH_REF_PREFIX \
	"refs/got/worktree/histedit/branch"

/* Reference pointing at the ID of the work tree's pre-edit base commit. */
#define GOT_WORKTREE_HISTEDIT_BASE_COMMIT_REF_PREFIX \
	"refs/got/worktree/histedit/base-commit"

/* Reference pointing at the ID of the current commit being edited. */
#define GOT_WORKTREE_HISTEDIT_COMMIT_REF_PREFIX \
	"refs/got/worktree/histedit/commit"

/* Symbolic reference pointing at the name of the merge source branch. */
#define GOT_WORKTREE_MERGE_BRANCH_REF_PREFIX "refs/got/worktree/merge/branch"

/* Reference pointing at the ID of the merge source branches's tip commit. */
#define GOT_WORKTREE_MERGE_COMMIT_REF_PREFIX "refs/got/worktree/merge/commit"

/* Reference pointing to temporary commits that may need trivial rebasing. */
#define GOT_WORKTREE_COMMIT_REF_PREFIX "refs/got/worktree/commit"
