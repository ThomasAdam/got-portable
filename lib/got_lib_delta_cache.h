/*
 * Copyright (c) 2019 Stefan Sperling <stsp@openbsd.org>
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

struct got_delta_cache;

const struct got_error *got_delta_cache_alloc(struct got_delta_cache **);
void got_delta_cache_free(struct got_delta_cache *);

const struct got_error *got_delta_cache_add(struct got_delta_cache *, off_t,
    uint8_t *, size_t);
const struct got_error *got_delta_cache_add_fulltext(struct got_delta_cache *,
    off_t , uint8_t *, size_t);
void got_delta_cache_get(uint8_t **, size_t *, uint8_t **, size_t *,
    struct got_delta_cache *, off_t);
