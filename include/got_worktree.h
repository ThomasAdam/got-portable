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

struct got_worktree;

const struct got_error *got_worktree_init(const char *, struct got_reference *,
    const char *, struct got_repository *);
const struct got_error *got_worktree_open(struct got_worktree **, const char *);
void got_worktree_close(struct got_worktree *);
char *got_worktree_get_repo_path(struct got_worktree *);
char  *got_worktree_get_head_ref_name(struct got_worktree *);
const struct got_error *got_worktree_change_head(struct got_worktree *,
    struct got_reference *, struct got_repository *);
const struct got_error *got_worktree_checkout_files(struct got_worktree *,
    struct got_repository *);
