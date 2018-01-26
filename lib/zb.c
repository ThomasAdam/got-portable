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

#include <sys/queue.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sha1.h>
#include <zlib.h>

#include "got_error.h"
#include "got_object.h"

#include "zb.h"

const struct got_error *
got_inflate_init(struct got_zstream_buf *zb, size_t bufsize)
{
	const struct got_error *err = NULL;

	memset(zb, 0, sizeof(*zb));

	zb->z.zalloc = Z_NULL;
	zb->z.zfree = Z_NULL;
	if (inflateInit(&zb->z) != Z_OK) {
		err = got_error(GOT_ERR_IO);
		goto done;
	}

	zb->inlen = zb->outlen = bufsize;

	zb->inbuf = calloc(1, zb->inlen);
	if (zb->inbuf == NULL) {
		err = got_error(GOT_ERR_NO_MEM);
		goto done;
	}

	zb->outbuf = calloc(1, zb->outlen);
	if (zb->outbuf == NULL) {
		err = got_error(GOT_ERR_NO_MEM);
		goto done;
	}

done:
	if (err)
		got_inflate_end(zb);
	return err;
}

const struct got_error *
got_inflate_read(struct got_zstream_buf *zb, FILE *f, size_t *outlenp)
{
	size_t last_total_out = zb->z.total_out;
	z_stream *z = &zb->z;
	int n, ret;

	z->next_out = zb->outbuf;
	z->avail_out = zb->outlen;

	do {
		if (z->avail_in == 0) {
			int i;
			n = fread(zb->inbuf, 1, zb->inlen, f);
			if (n == 0) {
				if (ferror(f))
					return got_ferror(f, GOT_ERR_IO);
				*outlenp = 0;
				return NULL;
			}
			z->next_in = zb->inbuf;
			z->avail_in = n;
		}
		ret = inflate(z, Z_SYNC_FLUSH);
	} while (ret == Z_OK && z->avail_out > 0);

	if (ret != Z_OK) {
		if (ret != Z_STREAM_END)
			return got_error(GOT_ERR_DECOMPRESSION);
		zb->flags |= GOT_ZSTREAM_F_HAVE_MORE;
	}

	*outlenp = z->total_out - last_total_out;
	return NULL;
}

void
got_inflate_end(struct got_zstream_buf *zb)
{
	free(zb->inbuf);
	free(zb->outbuf);
	inflateEnd(&zb->z);
}
