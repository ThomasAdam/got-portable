/*
 * Copyright (c) 2022 Stefan Sperling <stsp@openbsd.org>
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

typedef const struct got_error *(got_pack_index_progress_cb)(void *,
    uint32_t nobj_total, uint32_t nobj_indexed, uint32_t nobj_loose,
    uint32_t nobj_resolved);

const struct got_error *got_pack_hwrite(int, void *, int, SHA1_CTX *);

const struct got_error *
got_pack_index(struct got_pack *pack, int idxfd,
    FILE *tmpfile, FILE *delta_base_file, FILE *delta_accum_file,
    uint8_t *pack_sha1_expected,
    got_pack_index_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl);
