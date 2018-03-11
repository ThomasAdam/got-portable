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
	char *path_worktree_root;
	char *path_repo;
	char *path_prefix;

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
};

#define GOT_WORKTREE_GOT_DIR		".got"
#define GOT_WORKTREE_FILE_INDEX		"fileindex"
#define GOT_WORKTREE_REPOSITORY		"repository"
#define GOT_WORKTREE_PATH_PREFIX	"path-prefix"
#define GOT_WORKTREE_BASE_COMMIT	"base-commit"
#define GOT_WORKTREE_LOCK		"lock"
#define GOT_WORKTREE_FORMAT		"format"

#define GOT_WORKTREE_FORMAT_VERSION	1
