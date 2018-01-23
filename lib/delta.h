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

struct got_delta_base {
	SIMPLEQ_ENTRY(got_delta_base) entry;
	char *path_packfile;
	off_t offset;
	int type;
	size_t delta_size;
};

struct got_delta_chain {
	int nentries;
	SIMPLEQ_HEAD(, got_delta_base) entries;
};

struct got_delta_base *got_delta_base_open(const char *, int, off_t, size_t);
void got_delta_base_close(struct got_delta_base *);
const struct got_error *got_delta_chain_get_base_type(int *,
    struct got_delta_chain *) ;
const struct got_error *
got_delta_apply(struct got_repository *, FILE *, size_t, struct got_object *,
    FILE *);
