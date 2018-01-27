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

#include "path.h"
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
got_inflate_read(struct got_zstream_buf *zb, FILE *f, size_t *inlenp,
    size_t *outlenp)
{
	size_t last_total_out = zb->z.total_out;
	z_stream *z = &zb->z;
	int ret;

	z->next_out = zb->outbuf;
	z->avail_out = zb->outlen;

	*outlenp = 0;
	if (inlenp)
		*inlenp = 0;
	do {
		if (z->avail_in == 0) {
			size_t n = fread(zb->inbuf, 1, zb->inlen, f);
			if (n == 0) {
				if (ferror(f))
					return got_ferror(f, GOT_ERR_IO);
				break; /* EOF */
			}
			z->next_in = zb->inbuf;
			z->avail_in = n;
			if (inlenp)
				*inlenp += n;
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

const struct got_error *
got_inflate_to_mem(uint8_t **outbuf, size_t *outlen, FILE *f, size_t insize)
{
	const struct got_error *err;
	size_t inbytes, consumed, avail;
	struct got_zstream_buf zb;
	void *newbuf;

	err = got_inflate_init(&zb, 8192);
	if (err)
		return err;

	*outbuf = NULL;
	*outlen = 0;
	inbytes = 0;

	do {
		err = got_inflate_read(&zb, f, &consumed, &avail);
		if (err)
			return err;
		inbytes += consumed;
		if (avail == 0) {
			if (inbytes < insize)
				err = got_error(GOT_ERR_BAD_DELTA);
			break;
		}
		newbuf = reallocarray(*outbuf, 1, *outlen + avail);
		if (newbuf == NULL) {
			free(*outbuf);
			*outbuf = NULL;
			*outlen = 0;
			err = got_error(GOT_ERR_NO_MEM);
			goto done;
		}
		memcpy(newbuf + *outlen, zb.outbuf, avail);
		*outbuf = newbuf;
		*outlen += avail;
	} while (inbytes < insize);

done:
	got_inflate_end(&zb);
	return err;
}

const struct got_error *
got_inflate_to_tempfile(FILE **outfile, size_t *outlen, FILE *f)
{
	const struct got_error *err;
	size_t avail;
	struct got_zstream_buf zb;
	void *newbuf;

	*outfile = got_opentemp();
	if (*outfile == NULL)
		return got_error_from_errno();

	err = got_inflate_init(&zb, 8192);
	if (err)
		goto done;

	*outlen = 0;

	do {
		err = got_inflate_read(&zb, f, NULL, &avail);
		if (err)
			return err;
		if (avail > 0) {
			size_t n;
			n = fwrite(zb.outbuf, avail, 1, *outfile);
			if (n != 1) {
				err = got_ferror(*outfile, GOT_ERR_IO);
				goto done;
			}
			*outlen += avail;
		}
	} while (avail > 0);

done:
	if (err) {
		fclose(*outfile);
		*outfile = NULL;
	} else
		rewind(*outfile);
	got_inflate_end(&zb);
	return err;
}
