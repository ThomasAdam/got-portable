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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sha1.h>
#include <zlib.h>
#include <time.h>

#include "got_error.h"
#include "got_object.h"
#include "got_path.h"

#include "got_lib_inflate.h"

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

const struct got_error *
got_inflate_init(struct got_inflate_buf *zb, uint8_t *outbuf, size_t bufsize)
{
	const struct got_error *err = NULL;
	int zerr;

	memset(&zb->z, 0, sizeof(zb->z));

	zb->z.zalloc = Z_NULL;
	zb->z.zfree = Z_NULL;
	zerr = inflateInit(&zb->z);
	if (zerr != Z_OK) {
		if  (zerr == Z_ERRNO)
			return got_error_from_errno();
		if  (zerr == Z_MEM_ERROR) {
			errno = ENOMEM;
			return got_error_from_errno();
		}
		return got_error(GOT_ERR_DECOMPRESSION);
	}

	zb->inlen = zb->outlen = bufsize;

	zb->inbuf = calloc(1, zb->inlen);
	if (zb->inbuf == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	zb->flags = 0;
	if (outbuf == NULL) {
		zb->outbuf = calloc(1, zb->outlen);
		if (zb->outbuf == NULL) {
			err = got_error_from_errno();
			goto done;
		}
		zb->flags |= GOT_INFLATE_F_OWN_OUTBUF;
	} else
		zb->outbuf = outbuf;

done:
	if (err)
		got_inflate_end(zb);
	return err;
}

const struct got_error *
got_inflate_read(struct got_inflate_buf *zb, FILE *f, size_t *outlenp)
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
				ret = Z_STREAM_END;
				break;
			}
			z->next_in = zb->inbuf;
			z->avail_in = n;
		}
		ret = inflate(z, Z_SYNC_FLUSH);
	} while (ret == Z_OK && z->avail_out > 0);

	if (ret == Z_OK) {
		zb->flags |= GOT_INFLATE_F_HAVE_MORE;
	} else {
		if (ret != Z_STREAM_END)
			return got_error(GOT_ERR_DECOMPRESSION);
		zb->flags &= ~GOT_INFLATE_F_HAVE_MORE;
	}

	*outlenp = z->total_out - last_total_out;
	return NULL;
}

const struct got_error *
got_inflate_read_fd(struct got_inflate_buf *zb, int fd, size_t *outlenp)
{
	size_t last_total_out = zb->z.total_out;
	z_stream *z = &zb->z;
	int ret = Z_ERRNO;

	z->next_out = zb->outbuf;
	z->avail_out = zb->outlen;

	*outlenp = 0;
	do {
		if (z->avail_in == 0) {
			ssize_t n = read(fd, zb->inbuf, zb->inlen);
			if (n < 0)
				return got_error_from_errno();
			else if (n == 0) {
				/* EOF */
				ret = Z_STREAM_END;
				break;
			}
			z->next_in = zb->inbuf;
			z->avail_in = n;
		}
		ret = inflate(z, Z_SYNC_FLUSH);
	} while (ret == Z_OK && z->avail_out > 0);

	if (ret == Z_OK) {
		zb->flags |= GOT_INFLATE_F_HAVE_MORE;
	} else {
		if (ret != Z_STREAM_END)
			return got_error(GOT_ERR_DECOMPRESSION);
		zb->flags &= ~GOT_INFLATE_F_HAVE_MORE;
	}

	*outlenp = z->total_out - last_total_out;
	return NULL;
}

const struct got_error *
got_inflate_read_mmap(struct got_inflate_buf *zb, uint8_t *map, size_t offset,
    size_t len, size_t *outlenp, size_t *consumed)
{
	size_t last_total_out = zb->z.total_out;
	z_stream *z = &zb->z;
	int ret = Z_ERRNO;

	z->next_out = zb->outbuf;
	z->avail_out = zb->outlen;

	*outlenp = 0;
	*consumed = 0;

	do {
		size_t last_total_in = zb->z.total_in;
		if (z->avail_in == 0) {
			if (len == 0) {
				/* EOF */
				ret = Z_STREAM_END;
				break;
			}
			z->next_in = map + offset + *consumed;
			z->avail_in = MIN(zb->inlen, len);
			len -= z->avail_in;
		}
		ret = inflate(z, Z_SYNC_FLUSH);
		*consumed += z->total_in - last_total_in;
	} while (ret == Z_OK && z->avail_out > 0);

	if (ret == Z_OK) {
		zb->flags |= GOT_INFLATE_F_HAVE_MORE;
	} else {
		if (ret != Z_STREAM_END)
			return got_error(GOT_ERR_DECOMPRESSION);
		zb->flags &= ~GOT_INFLATE_F_HAVE_MORE;
	}

	*outlenp = z->total_out - last_total_out;
	return NULL;
}

void
got_inflate_end(struct got_inflate_buf *zb)
{
	free(zb->inbuf);
	if (zb->flags & GOT_INFLATE_F_OWN_OUTBUF)
		free(zb->outbuf);
	inflateEnd(&zb->z);
}

const struct got_error *
got_inflate_to_mem(uint8_t **outbuf, size_t *outlen, FILE *f)
{
	const struct got_error *err;
	size_t avail;
	struct got_inflate_buf zb;
	void *newbuf;
	int nbuf = 1;

	*outbuf = calloc(1, GOT_INFLATE_BUFSIZE);
	if (*outbuf == NULL)
		return got_error_from_errno();
	err = got_inflate_init(&zb, *outbuf, GOT_INFLATE_BUFSIZE);
	if (err)
		return err;

	*outlen = 0;

	do {
		err = got_inflate_read(&zb, f, &avail);
		if (err)
			goto done;
		*outlen += avail;
		if (zb.flags & GOT_INFLATE_F_HAVE_MORE) {
			nbuf++;
			newbuf = recallocarray(*outbuf, nbuf - 1, nbuf,
			   GOT_INFLATE_BUFSIZE);
			if (newbuf == NULL) {
				err = got_error_from_errno();
				free(*outbuf);
				*outbuf = NULL;
				*outlen = 0;
				goto done;
			}
			*outbuf = newbuf;
			zb.outbuf = newbuf + *outlen;
			zb.outlen = (nbuf * GOT_INFLATE_BUFSIZE) - *outlen;
		}
	} while (zb.flags & GOT_INFLATE_F_HAVE_MORE);

done:
	got_inflate_end(&zb);
	return err;
}

const struct got_error *
got_inflate_to_mem_fd(uint8_t **outbuf, size_t *outlen, int infd)
{
	const struct got_error *err;
	size_t avail;
	struct got_inflate_buf zb;
	void *newbuf;
	int nbuf = 1;

	*outbuf = calloc(1, GOT_INFLATE_BUFSIZE);
	if (*outbuf == NULL)
		return got_error_from_errno();
	err = got_inflate_init(&zb, *outbuf, GOT_INFLATE_BUFSIZE);
	if (err)
		goto done;

	*outlen = 0;

	do {
		err = got_inflate_read_fd(&zb, infd, &avail);
		if (err)
			goto done;
		*outlen += avail;
		if (zb.flags & GOT_INFLATE_F_HAVE_MORE) {
			nbuf++;
			newbuf = recallocarray(*outbuf, nbuf - 1, nbuf,
			    GOT_INFLATE_BUFSIZE);
			if (newbuf == NULL) {
				err = got_error_from_errno();
				free(*outbuf);
				*outbuf = NULL;
				*outlen = 0;
				goto done;
			}
			*outbuf = newbuf;
			zb.outbuf = newbuf + *outlen;
			zb.outlen = (nbuf * GOT_INFLATE_BUFSIZE) - *outlen;
		}
	} while (zb.flags & GOT_INFLATE_F_HAVE_MORE);

done:
	got_inflate_end(&zb);
	return err;
}

const struct got_error *
got_inflate_to_mem_mmap(uint8_t **outbuf, size_t *outlen, uint8_t *map,
    size_t offset, size_t len)
{
	const struct got_error *err;
	size_t avail, consumed;
	struct got_inflate_buf zb;
	void *newbuf;
	int nbuf = 1;

	*outbuf = calloc(1, GOT_INFLATE_BUFSIZE);
	if (*outbuf == NULL)
		return got_error_from_errno();
	err = got_inflate_init(&zb, *outbuf, GOT_INFLATE_BUFSIZE);
	if (err) {
		free(*outbuf);
		*outbuf = NULL;
		return err;
	}

	*outlen = 0;

	do {
		err = got_inflate_read_mmap(&zb, map, offset, len, &avail,
		    &consumed);
		if (err)
			goto done;
		offset += consumed;
		len -= consumed;
		*outlen += avail;
		if (len == 0)
			break;
		if (zb.flags & GOT_INFLATE_F_HAVE_MORE) {
			nbuf++;
			newbuf = recallocarray(*outbuf, nbuf - 1, nbuf,
			    GOT_INFLATE_BUFSIZE);
			if (newbuf == NULL) {
				err = got_error_from_errno();
				free(*outbuf);
				*outbuf = NULL;
				*outlen = 0;
				goto done;
			}
			*outbuf = newbuf;
			zb.outbuf = newbuf + *outlen;
			zb.outlen = (nbuf * GOT_INFLATE_BUFSIZE) - *outlen;
		}
	} while (zb.flags & GOT_INFLATE_F_HAVE_MORE);
done:
	got_inflate_end(&zb);
	return err;
}

const struct got_error *
got_inflate_to_fd(size_t *outlen, FILE *infile, int outfd)
{
	const struct got_error *err = NULL;
	size_t avail;
	struct got_inflate_buf zb;

	err = got_inflate_init(&zb, NULL, GOT_INFLATE_BUFSIZE);
	if (err)
		goto done;

	*outlen = 0;

	do {
		err = got_inflate_read(&zb, infile, &avail);
		if (err)
			goto done;
		if (avail > 0) {
			ssize_t n;
			n = write(outfd, zb.outbuf, avail);
			if (n != avail) {
				err = got_error_from_errno();
				goto done;
			}
			*outlen += avail;
		}
	} while (zb.flags & GOT_INFLATE_F_HAVE_MORE);

done:
	if (err == NULL) {
		if (lseek(outfd, SEEK_SET, 0) == -1)
			err = got_error_from_errno();
	}
	got_inflate_end(&zb);
	return err;
}

const struct got_error *
got_inflate_to_file(size_t *outlen, FILE *infile, FILE *outfile)
{
	const struct got_error *err;
	size_t avail;
	struct got_inflate_buf zb;

	err = got_inflate_init(&zb, NULL, GOT_INFLATE_BUFSIZE);
	if (err)
		goto done;

	*outlen = 0;

	do {
		err = got_inflate_read(&zb, infile, &avail);
		if (err)
			goto done;
		if (avail > 0) {
			size_t n;
			n = fwrite(zb.outbuf, avail, 1, outfile);
			if (n != 1) {
				err = got_ferror(outfile, GOT_ERR_IO);
				goto done;
			}
			*outlen += avail;
		}
	} while (zb.flags & GOT_INFLATE_F_HAVE_MORE);

done:
	if (err == NULL)
		rewind(outfile);
	got_inflate_end(&zb);
	return err;
}

const struct got_error *
got_inflate_to_file_fd(size_t *outlen, int infd, FILE *outfile)
{
	const struct got_error *err;
	size_t avail;
	struct got_inflate_buf zb;

	err = got_inflate_init(&zb, NULL, GOT_INFLATE_BUFSIZE);
	if (err)
		goto done;

	*outlen = 0;

	do {
		err = got_inflate_read_fd(&zb, infd, &avail);
		if (err)
			goto done;
		if (avail > 0) {
			size_t n;
			n = fwrite(zb.outbuf, avail, 1, outfile);
			if (n != 1) {
				err = got_ferror(outfile, GOT_ERR_IO);
				goto done;
			}
			*outlen += avail;
		}
	} while (zb.flags & GOT_INFLATE_F_HAVE_MORE);

done:
	if (err == NULL)
		rewind(outfile);
	got_inflate_end(&zb);
	return err;
}

const struct got_error *
got_inflate_to_file_mmap(size_t *outlen, uint8_t *map, size_t offset,
    size_t len, FILE *outfile)
{
	const struct got_error *err;
	size_t avail;
	struct got_inflate_buf zb;
	size_t consumed;

	err = got_inflate_init(&zb, NULL, GOT_INFLATE_BUFSIZE);
	if (err)
		goto done;

	*outlen = 0;

	do {
		err = got_inflate_read_mmap(&zb, map, offset, len, &avail,
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
			*outlen += avail;
		}
	} while (zb.flags & GOT_INFLATE_F_HAVE_MORE);

done:
	if (err == NULL)
		rewind(outfile);
	got_inflate_end(&zb);
	return err;
}
