/*
 * Copyright (c) 2021 Stefan Sperling <stsp@openbsd.org>
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
 * Write pack file data into the provided open packfile handle, for all
 * objects reachable via the commits listed in 'ours'.
 * Exclude any objects for commits listed in 'theirs' if 'theirs' is not NULL.
 * Return the SHA1 digest of the resulting pack file in pack_sha1 which must
 * be pre-allocated by the caller with at least SHA1_DIGEST_LENGTH bytes.
 */
const struct got_error *got_pack_create(uint8_t *pack_sha1, int packfd,
    struct got_object_id **theirs, int ntheirs,
    struct got_object_id **ours, int nours,
    struct got_repository *repo, int loose_obj_only, int allow_empty,
    got_pack_progress_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg);
