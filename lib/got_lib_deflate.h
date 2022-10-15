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

struct got_deflate_checksum {
	/* If not NULL, mix output bytes into this CRC checksum. */
	uint32_t *output_crc;

	/* If not NULL, mix output bytes into this SHA1 context. */
	SHA1_CTX *output_sha1;
};

struct got_deflate_buf {
	z_stream z;
	uint8_t *inbuf;
	size_t inlen;
	uint8_t *outbuf;
	size_t outlen;
	int flags;
#define GOT_DEFLATE_F_HAVE_MORE		0x01
#define GOT_DEFLATE_F_OWN_OUTBUF	0x02
};

#define GOT_DEFLATE_BUFSIZE		8192

const struct got_error *got_deflate_init(struct got_deflate_buf *, uint8_t *,
    size_t);
const struct got_error *got_deflate_read(struct got_deflate_buf *, FILE *,
    off_t, size_t *, off_t *);
const struct got_error *got_deflate_read_mmap(struct got_deflate_buf *,
    uint8_t *, size_t, size_t, size_t *, size_t *);
void got_deflate_end(struct got_deflate_buf *);
const struct got_error *got_deflate_to_fd(off_t *, FILE *, off_t, int,
    struct got_deflate_checksum *);
const struct got_error *got_deflate_to_fd_mmap(off_t *, uint8_t *,
    size_t, size_t, int, struct got_deflate_checksum *);
const struct got_error *got_deflate_to_file(off_t *, FILE *, off_t, FILE *,
    struct got_deflate_checksum *);
const struct got_error *got_deflate_to_file_mmap(off_t *, uint8_t *,
    size_t, size_t, FILE *, struct got_deflate_checksum *);
const struct got_error *got_deflate_flush(struct got_deflate_buf *, FILE *,
    struct got_deflate_checksum *, off_t *);
const struct got_error *got_deflate_append_to_file_mmap(
    struct got_deflate_buf *, off_t *, uint8_t *, size_t, size_t, FILE *,
    struct got_deflate_checksum *);
const struct got_error *got_deflate_to_mem_mmap(uint8_t **, size_t *, size_t *,
    struct got_deflate_checksum *, uint8_t *, size_t, size_t);
