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

#include <sys/queue.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sha1.h>
#include <sha2.h>
#include <zlib.h>
#include <time.h>

#include "got_error.h"
#include "got_object.h"
#include "got_path.h"

#include "got_lib_deflate.h"
#include "got_lib_hash.h"
#include "got_lib_poll.h"

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

const struct got_error *
got_deflate_init(struct got_deflate_buf *zb, uint8_t *outbuf, size_t bufsize)
{
	const struct got_error *err = NULL;
	int zerr;

	memset(zb, 0, sizeof(*zb));

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

	if (csum->output_ctx)
		got_hash_update(csum->output_ctx, buf, len);
}

const struct got_error *
got_deflate_read(struct got_deflate_buf *zb, FILE *f, off_t len,
    size_t *outlenp, off_t *consumed)
{
	size_t last_total_out = zb->z.total_out;
	z_stream *z = &zb->z;
	int ret = Z_ERRNO;

	z->next_out = zb->outbuf;
	z->avail_out = zb->outlen;

	*outlenp = 0;
	*consumed = 0;
	do {
		size_t last_total_in = z->total_in;
		if (z->avail_in == 0) {
			size_t n = 0;
			if (*consumed < len) {
				n = fread(zb->inbuf, 1,
				    MIN(zb->inlen, len - *consumed), f);
			}
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

static const struct got_error *
deflate_read_mmap(struct got_deflate_buf *zb, uint8_t *map, size_t offset,
    size_t len, size_t *outlenp, size_t *consumed, int flush_on_eof)
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
			if (len - *consumed > UINT_MAX)
				z->avail_in = UINT_MAX;
			else
				z->avail_in = len - *consumed;
			if (z->avail_in == 0) {
				/* EOF */
				if (flush_on_eof)
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

const struct got_error *
got_deflate_read_mmap(struct got_deflate_buf *zb, uint8_t *map, size_t offset,
    size_t len, size_t *outlenp, size_t *consumed)
{
	return deflate_read_mmap(zb, map, offset, len, outlenp, consumed, 1);
}

const struct got_error *
got_deflate_flush(struct got_deflate_buf *zb, FILE *outfile,
    struct got_deflate_checksum *csum, off_t *outlenp)
{
	int ret;
	size_t n;
	z_stream *z = &zb->z;

	if (z->avail_in != 0)
		return got_error_msg(GOT_ERR_COMPRESSION,
		    "cannot flush zb with pending input data");

	do {
		size_t avail, last_total_out = zb->z.total_out;

		z->next_out = zb->outbuf;
		z->avail_out = zb->outlen;

		ret = deflate(z, Z_FINISH);
		if (ret != Z_STREAM_END && ret != Z_OK)
			return got_error(GOT_ERR_COMPRESSION);

		avail = z->total_out - last_total_out;
		if (avail > 0) {
			n = fwrite(zb->outbuf, avail, 1, outfile);
			if (n != 1)
				return got_ferror(outfile, GOT_ERR_IO);
			if (csum)
				csum_output(csum, zb->outbuf, avail);
			if (outlenp)
				*outlenp += avail;
		}
	} while (ret != Z_STREAM_END);

	zb->flags &= ~GOT_DEFLATE_F_HAVE_MORE;
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
got_deflate_to_fd(off_t *outlen, FILE *infile, off_t len, int outfd,
    struct got_deflate_checksum *csum)
{
	const struct got_error *err;
	size_t avail;
	off_t consumed;
	struct got_deflate_buf zb;

	err = got_deflate_init(&zb, NULL, GOT_DEFLATE_BUFSIZE);
	if (err)
		goto done;

	*outlen = 0;

	do {
		err = got_deflate_read(&zb, infile, len, &avail, &consumed);
		if (err)
			goto done;
		len -= consumed;
		if (avail > 0) {
			err = got_poll_write_full(outfd, zb.outbuf, avail);
			if (err)
				goto done;
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
got_deflate_to_fd_mmap(off_t *outlen, uint8_t *map, size_t offset,
    size_t len, int outfd, struct got_deflate_checksum *csum)
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
			err = got_poll_write_full(outfd, zb.outbuf, avail);
			if (err)
				goto done;
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
got_deflate_to_file(off_t *outlen, FILE *infile, off_t len,
    FILE *outfile, struct got_deflate_checksum *csum)
{
	const struct got_error *err;
	size_t avail;
	off_t consumed;
	struct got_deflate_buf zb;

	err = got_deflate_init(&zb, NULL, GOT_DEFLATE_BUFSIZE);
	if (err)
		goto done;

	*outlen = 0;

	do {
		err = got_deflate_read(&zb, infile, len, &avail, &consumed);
		if (err)
			goto done;
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

const struct got_error *
got_deflate_to_file_mmap(off_t *outlen, uint8_t *map, size_t offset,
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

const struct got_error *
got_deflate_append_to_file_mmap(struct got_deflate_buf *zb, off_t *outlen,
    uint8_t *map, size_t offset, size_t len, FILE *outfile,
    struct got_deflate_checksum *csum)
{
	const struct got_error *err;
	size_t avail, consumed;

	do {
		err = deflate_read_mmap(zb, map, offset, len, &avail,
		    &consumed, 0);
		if (err)
			break;
		offset += consumed;
		len -= consumed;
		if (avail > 0) {
			size_t n;
			n = fwrite(zb->outbuf, avail, 1, outfile);
			if (n != 1) {
				err = got_ferror(outfile, GOT_ERR_IO);
				break;
			}
			if (csum)
				csum_output(csum, zb->outbuf, avail);
			if (outlen)
				*outlen += avail;
		}
	} while ((zb->flags & GOT_DEFLATE_F_HAVE_MORE) && len > 0);

	return err;
}

const struct got_error *
got_deflate_to_mem_mmap(uint8_t **outbuf, size_t *outlen,
    size_t *consumed_total, struct got_deflate_checksum *csum, uint8_t *map,
    size_t offset, size_t len)
{
	const struct got_error *err;
	size_t avail, consumed;
	struct got_deflate_buf zb;
	void *newbuf;
	size_t nbuf = 1;

	if (outbuf) {
		*outbuf = malloc(GOT_DEFLATE_BUFSIZE);
		if (*outbuf == NULL)
			return got_error_from_errno("malloc");
		err = got_deflate_init(&zb, *outbuf, GOT_DEFLATE_BUFSIZE);
		if (err) {
			free(*outbuf);
			*outbuf = NULL;
			return err;
		}
	} else {
		err = got_deflate_init(&zb, NULL, GOT_DEFLATE_BUFSIZE);
		if (err)
			return err;
	}

	*outlen = 0;
	if (consumed_total)
		*consumed_total = 0;
	do {
		err = got_deflate_read_mmap(&zb, map, offset, len, &avail,
		    &consumed);
		if (err)
			goto done;
		offset += consumed;
		if (consumed_total)
			*consumed_total += consumed;
		len -= consumed;
		if (avail > 0 && csum)
			csum_output(csum, zb.outbuf, avail);
		*outlen += avail;
		if ((zb.flags & GOT_DEFLATE_F_HAVE_MORE) && outbuf != NULL) {
			newbuf = reallocarray(*outbuf, ++nbuf,
			    GOT_DEFLATE_BUFSIZE);
			if (newbuf == NULL) {
				err = got_error_from_errno("reallocarray");
				free(*outbuf);
				*outbuf = NULL;
				*outlen = 0;
				goto done;
			}
			*outbuf = newbuf;
			zb.outbuf = newbuf + *outlen;
			zb.outlen = (nbuf * GOT_DEFLATE_BUFSIZE) - *outlen;
		}
	} while (zb.flags & GOT_DEFLATE_F_HAVE_MORE);
done:
	got_deflate_end(&zb);
	return err;
}
