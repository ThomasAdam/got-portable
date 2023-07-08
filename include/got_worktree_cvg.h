/*
 * Copyright (c) 2018, 2019, 2020 Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2023 Josh Rickmar <jrick@zettaport.com>
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

/*
 * Create a new commit from changes in the work tree.
 * Return the ID of the newly created commit.
 * The worktree's base commit will be set to this new commit.
 * Files unaffected by this commit operation will retain their
 * current base commit.
 * An author and a non-empty log message must be specified.
 * The name of the committer is optional (may be NULL).
 * If a path to be committed contains a symlink which points outside
 * of the path space under version control, raise an error unless
 * committing of such paths is being forced by the caller.
 */
const struct got_error *got_worktree_cvg_commit(struct got_object_id **,
    struct got_worktree *, struct got_pathlist_head *, const char *,
    const char *, int, int, int, got_worktree_commit_msg_cb, void *,
    got_worktree_status_cb, void *, const char *, const char *, const char *,
    const char *, int, const struct got_remote_repo *, got_cancel_cb,
    struct got_repository *);

/*
 * Get the reference name for a temporary commit to be trivially rebased
 * over a remote branch.
 */
const struct got_error *got_worktree_cvg_get_commit_ref_name(char **,
    struct got_worktree *);
