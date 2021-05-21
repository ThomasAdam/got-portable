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
	char *inbuf;
	size_t inlen;
	char *outbuf;
	size_t outlen;
	int flags;
#define GOT_DEFLATE_F_HAVE_MORE		0x01
#define GOT_DEFLATE_F_OWN_OUTBUF	0x02
	struct got_deflate_checksum *csum;
};

#define GOT_DEFLATE_BUFSIZE		8192

const struct got_error *got_deflate_init(struct got_deflate_buf *, uint8_t *,
    size_t, struct got_deflate_checksum *);
const struct got_error *got_deflate_read(struct got_deflate_buf *, FILE *,
    size_t *);
void got_deflate_end(struct got_deflate_buf *);
const struct got_error *got_deflate_to_file(size_t *, FILE *, FILE *,
    struct got_deflate_checksum *);
