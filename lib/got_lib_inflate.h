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

struct got_inflate_buf {
	z_stream z;
	char *inbuf;
	size_t inlen;
	char *outbuf;
	size_t outlen;
	int flags;
#define GOT_INFLATE_F_HAVE_MORE		0x01
#define GOT_INFLATE_F_OWN_OUTBUF	0x02
};

#define GOT_INFLATE_BUFSIZE		8192

const struct got_error *got_inflate_init(struct got_inflate_buf *, uint8_t *,
    size_t);
const struct got_error *got_inflate_read(struct got_inflate_buf *, FILE *,
    size_t *);
const struct got_error *got_inflate_read_fd(struct got_inflate_buf *, int,
    size_t *);
const struct got_error *got_inflate_read_mmap(struct got_inflate_buf *,
    uint8_t *, size_t, size_t, size_t *, size_t *);
void got_inflate_end(struct got_inflate_buf *);
const struct got_error *got_inflate_to_mem(uint8_t **, size_t *, FILE *);
const struct got_error *got_inflate_to_mem_fd(uint8_t **, size_t *, int);
const struct got_error *got_inflate_to_mem_mmap(uint8_t **, size_t *, uint8_t *,
    size_t, size_t);
const struct got_error *got_inflate_to_file(size_t *, FILE *, FILE *);
const struct got_error *got_inflate_to_file_fd(size_t *, int, FILE *);
const struct got_error *got_inflate_to_fd(size_t *, FILE *, int);
const struct got_error *got_inflate_to_file_mmap(size_t *, uint8_t *, size_t,
    size_t, FILE *);
