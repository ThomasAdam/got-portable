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

struct got_delta {
	SIMPLEQ_ENTRY(got_delta) entry;
	off_t offset;
	size_t tslen;
	int type;
	size_t size;
	off_t data_offset;
	uint8_t *delta_buf;
	size_t delta_len;
};

struct got_delta_chain {
	int nentries;
	SIMPLEQ_HEAD(, got_delta) entries;
};

#define GOT_DELTA_CHAIN_RECURSION_MAX	500

struct got_delta *got_delta_open(off_t, size_t, int, size_t, off_t,
    uint8_t *, size_t);
const struct got_error *got_delta_chain_get_base_type(int *,
    struct got_delta_chain *);
const struct got_error *got_delta_get_sizes(uint64_t *, uint64_t *,
    const uint8_t *, size_t);
const struct got_error *got_delta_apply_in_mem(uint8_t *, size_t,
    const uint8_t *, size_t, uint8_t *, size_t *, size_t);
const struct got_error *got_delta_apply(FILE *, const uint8_t *, size_t,
    FILE *, size_t *);

/*
 * The amount of result data we may keep in RAM while applying deltas.
 * Data larger than this is written to disk during delta application (slow).
 */
#define GOT_DELTA_RESULT_SIZE_CACHED_MAX	(4 * 1024 * 1024) /* bytes */

/*
 * Definitions for delta data streams.
 */

#define GOT_DELTA_STREAM_LENGTH_MIN	4	/* bytes */

/*
 * A delta stream begins with two size fields. The first specifies the
 * size of the delta base, and the second describes the expected size of
 * the data which results from applying the delta to the delta base.
 *
 * Each size field uses a variable length encoding:
 * size0...sizeN form a 7+7+7+...+7 bit integer, where size0 is the
 * least significant part and sizeN is the most significant part.
 * If the MSB of a size byte is set, an additional size byte follows.
 */
#define GOT_DELTA_SIZE_VAL_MASK	0x7f
#define GOT_DELTA_SIZE_SHIFT	7
#define GOT_DELTA_SIZE_MORE	0x80

/*
 * The rest of the delta stream contains copy instructions.
 *
 * A base copy instruction copies N bytes starting at offset X from the delta
 * base to the output. Base copy instructions begin with a byte which has its
 * MSB set. The remaining bits of this byte describe how many offset and
 * length value bytes follow.
 * The offset X is encoded in 1 to 4 bytes, and the length N is encoded in
 * 1 to 3 bytes. For both values, the first byte contributes the least
 * significant part and the last byte which is present contributes the
 * most significant part.
 * If the offset value is omitted, an offset of zero is implied.
 * If the length value is omitted, a default length of 65536 bytes is implied.
 *
 * An inline copy instruction copies data from the delta stream to the output.
 * Such instructions begin with one byte which does not have the MSB set
 * and which specifies the length of the inline data which follows (i.e.
 * at most 127 bytes). A length value of zero is invalid.
 */

#define GOT_DELTA_BASE_COPY	0x80

#define GOT_DELTA_COPY_OFF1	0x01	/* byte 1 of offset is present */
#define GOT_DELTA_COPY_OFF2	0x02	/* byte 2 of offset is present */
#define GOT_DELTA_COPY_OFF3	0x04	/* byte 3 of offset is present */
#define GOT_DELTA_COPY_OFF4	0x08	/* byte 4 of offset is present */

#define GOT_DELTA_COPY_LEN1	0x10	/* byte 1 of length is present */
#define GOT_DELTA_COPY_LEN2	0x20	/* byte 2 of length is present */
#define GOT_DELTA_COPY_LEN3	0x40	/* byte 3 of length is present */

#define GOT_DELTA_COPY_DEFAULT_OFF	0x0	/* default offset if omitted */
#define GOT_DELTA_COPY_DEFAULT_LEN	0x10000 /* default length if omitted */
