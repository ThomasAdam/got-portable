/*
 * Copyright (c) 2022 Omar Polo <op@openbsd.org>
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
 * A callback that gets invoked during the patch application.
 *
 * Receives the old and new path, a status code, if an error occurred while
 * applying the patch, and a hunk applied with offset or its error.
 */
typedef const struct got_error *(*got_patch_progress_cb)(void *,
    const char *, const char *, unsigned char, const struct got_error *,
    int, int, int, int, int, int, const struct got_error *);

/*
 * Apply the (already opened) patch to the repository and register the
 * status of the added and removed files.
 *
 * The patch file descriptor *must* be seekable.
 */
const struct got_error *
got_patch(int, struct got_worktree *, struct got_repository *, int, int,
    int, struct got_object_id *, got_patch_progress_cb, void *,
    got_cancel_cb, void *);
