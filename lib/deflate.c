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


#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <time.h>

#include "got_error.h"
#include "got_object.h"
#include "got_path.h"

#include "got_lib_deflate.h"

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

const struct got_error *
got_deflate_init(struct got_deflate_buf *zb, uint8_t *outbuf, size_t bufsize)
{
	const struct got_error *err = NULL;
	int zerr;

	memset(&zb->z, 0, sizeof(zb->z));

	zb->z.zalloc = Z_NULL;
	zb->z.zfree = Z_NULL;
	zerr = deflateInit(&zb->z, Z_DEFAULT_COMPRESSION);
	if (zerr != Z_OK) {
		if  (zerr == Z_ERRNO)
			return got_error_from_errno("deflateInit");
		if  (zerr == Z_MEM_ERROR) {
			errno = ENOMEM;
			return got_error_from_errno("deflateInit");
		}
		return got_error(GOT_ERR_COMPRESSION);
	}

	zb->inlen = zb->outlen = bufsize;

	zb->inbuf = calloc(1, zb->inlen);
	if (zb->inbuf == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}

	zb->flags = 0;
	if (outbuf == NULL) {
		zb->outbuf = calloc(1, zb->outlen);
		if (zb->outbuf == NULL) {
			err = got_error_from_errno("calloc");
			goto done;
		}
		zb->flags |= GOT_DEFLATE_F_OWN_OUTBUF;
	} else
		zb->outbuf = outbuf;
done:
	if (err)
		got_deflate_end(zb);
	return err;
}

static void
csum_output(struct got_deflate_checksum *csum, const uint8_t *buf, size_t len)
{
	if (csum->output_crc)
		*csum->output_crc = crc32(*csum->output_crc, buf, len);

	if (csum->output_sha1)
		SHA1Update(csum->output_sha1, buf, len);
}

const struct got_error *
got_deflate_read(struct got_deflate_buf *zb, FILE *f, size_t *outlenp)
{
	size_t last_total_out = zb->z.total_out;
	z_stream *z = &zb->z;
	int ret = Z_ERRNO;

	z->next_out = zb->outbuf;
	z->avail_out = zb->outlen;

	*outlenp = 0;
	do {
		if (z->avail_in == 0) {
			size_t n = fread(zb->inbuf, 1, zb->inlen, f);
			if (n == 0) {
				if (ferror(f))
					return got_ferror(f, GOT_ERR_IO);
				/* EOF */
				ret = deflate(z, Z_FINISH);
				break;
			}
			z->next_in = zb->inbuf;
			z->avail_in = n;
		}
		ret = deflate(z, Z_NO_FLUSH);
	} while (ret == Z_OK && z->avail_out > 0);

	if (ret == Z_OK) {
		zb->flags |= GOT_DEFLATE_F_HAVE_MORE;
	} else {
		if (ret != Z_STREAM_END)
			return got_error(GOT_ERR_COMPRESSION);
		zb->flags &= ~GOT_DEFLATE_F_HAVE_MORE;
	}

	*outlenp = z->total_out - last_total_out;
	return NULL;
}

const struct got_error *
got_deflate_read_mmap(struct got_deflate_buf *zb, uint8_t *map, size_t offset,
    size_t len, size_t *outlenp, size_t *consumed)
{
	z_stream *z = &zb->z;
	size_t last_total_out = z->total_out;
	int ret = Z_ERRNO;

	z->next_out = zb->outbuf;
	z->avail_out = zb->outlen;

	*outlenp = 0;
	*consumed = 0;
	do {
		size_t last_total_in = z->total_in;
		if (z->avail_in == 0) {
			z->next_in = map + offset + *consumed;
			z->avail_in = len - *consumed;
			if (z->avail_in == 0) {
				/* EOF */
				ret = deflate(z, Z_FINISH);
				break;
			}
		}
		ret = deflate(z, Z_NO_FLUSH);
		*consumed += z->total_in - last_total_in;
	} while (ret == Z_OK && z->avail_out > 0);

	if (ret == Z_OK) {
		zb->flags |= GOT_DEFLATE_F_HAVE_MORE;
	} else {
		if (ret != Z_STREAM_END)
			return got_error(GOT_ERR_COMPRESSION);
		zb->flags &= ~GOT_DEFLATE_F_HAVE_MORE;
	}

	*outlenp = z->total_out - last_total_out;
	return NULL;
}

void
got_deflate_end(struct got_deflate_buf *zb)
{
	free(zb->inbuf);
	if (zb->flags & GOT_DEFLATE_F_OWN_OUTBUF)
		free(zb->outbuf);
	deflateEnd(&zb->z);
}

const struct got_error *
got_deflate_to_file(size_t *outlen, FILE *infile, FILE *outfile,
    struct got_deflate_checksum *csum)
{
	const struct got_error *err;
	size_t avail;
	struct got_deflate_buf zb;

	err = got_deflate_init(&zb, NULL, GOT_DEFLATE_BUFSIZE);
	if (err)
		goto done;

	*outlen = 0;

	do {
		err = got_deflate_read(&zb, infile, &avail);
		if (err)
			goto done;
		if (avail > 0) {
			size_t n;
			n = fwrite(zb.outbuf, avail, 1, outfile);
			if (n != 1) {
				err = got_ferror(outfile, GOT_ERR_IO);
				goto done;
			}
			if (csum)
				csum_output(csum, zb.outbuf, avail);
			*outlen += avail;
		}
	} while (zb.flags & GOT_DEFLATE_F_HAVE_MORE);

done:
	got_deflate_end(&zb);
	return err;
}

const struct got_error *
got_deflate_to_file_mmap(size_t *outlen, uint8_t *map, size_t offset,
    size_t len, FILE *outfile, struct got_deflate_checksum *csum)
{
	const struct got_error *err;
	size_t avail, consumed;
	struct got_deflate_buf zb;

	err = got_deflate_init(&zb, NULL, GOT_DEFLATE_BUFSIZE);
	if (err)
		goto done;

	*outlen = 0;
	do {
		err = got_deflate_read_mmap(&zb, map, offset, len, &avail,
		    &consumed);
		if (err)
			goto done;
		offset += consumed;
		len -= consumed;
		if (avail > 0) {
			size_t n;
			n = fwrite(zb.outbuf, avail, 1, outfile);
			if (n != 1) {
				err = got_ferror(outfile, GOT_ERR_IO);
				goto done;
			}
			if (csum)
				csum_output(csum, zb.outbuf, avail);
			*outlen += avail;
		}
	} while (zb.flags & GOT_DEFLATE_F_HAVE_MORE);

done:
	got_deflate_end(&zb);
	return err;
}
