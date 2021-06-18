/*
 * Copyright (c) 2020 Ori Bernstein
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

struct got_delta_block {
	off_t		len;
	off_t		offset;
	uint64_t	hash;
};

struct got_delta_table {
	struct got_delta_block	*blocks;
	int			nblocks;
	int			nalloc;
};

struct got_delta_instruction {
	int	copy;
	off_t	offset;
	off_t	len;
};

enum {
	GOT_DELTIFY_MINCHUNK	= 128,
	GOT_DELTIFY_MAXCHUNK	= 8192,
	GOT_DELTIFY_SPLITMASK	= (1 << 8) - 1,
	
};

const struct got_error *got_deltify_init(struct got_delta_table **dt, FILE *f,
    off_t fileoffset, off_t filesize);
const struct got_error *got_deltify(struct got_delta_instruction **deltas,
    int *ndeltas, FILE *f, off_t fileoffset, off_t filesize,
    struct got_delta_table *dt, FILE *basefile, off_t basefile_offset0,
    off_t basefile_size);
void got_deltify_free(struct got_delta_table *dt);
