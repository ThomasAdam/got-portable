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
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <zlib.h>
#include <time.h>
#include <zlib.h>

#include "got_compat.h"
#include "got_error.h"
#include "got_repository.h"
#include "got_object.h"
#include "got_path.h"

#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

struct got_delta *
got_delta_open(off_t offset, size_t tslen, int type, size_t size,
    off_t data_offset)
{
	struct got_delta *delta;

	delta = malloc(sizeof(*delta));
	if (delta == NULL)
		return NULL;

	delta->type = type;
	delta->offset = offset;
	delta->tslen = tslen;
	delta->size = size;
	delta->data_offset = data_offset;
	return delta;
}

const struct got_error *
got_delta_chain_get_base_type(int *type, struct got_delta_chain *deltas)
{
	struct got_delta *delta;

	/* The first delta in the chain should represent the base object. */
	delta = STAILQ_FIRST(&deltas->entries);
	if (delta->type == GOT_OBJ_TYPE_COMMIT ||
	    delta->type == GOT_OBJ_TYPE_TREE ||
	    delta->type == GOT_OBJ_TYPE_BLOB ||
	    delta->type == GOT_OBJ_TYPE_TAG) {
		*type = delta->type;
		return NULL;
	}

	return got_error(GOT_ERR_BAD_DELTA_CHAIN);
}

/* Fetch another (required) byte from the delta stream. */
static const struct got_error *
next_delta_byte(const uint8_t **p, size_t *remain)
{
	if (--(*remain) == 0)
		return got_error_msg(GOT_ERR_BAD_DELTA,
		    "delta data truncated");
	(*p)++;
	return NULL;
}

static const struct got_error *
parse_size(uint64_t *size, const uint8_t **p, size_t *remain)
{
	const struct got_error *err = NULL;
	int i = 0;

	*size = 0;
	do {
		/* We do not support size values which don't fit in 64 bit. */
		if (i > 9)
			return got_error(GOT_ERR_NO_SPACE);

		if (i == 0)
			*size = ((**p) & GOT_DELTA_SIZE_VAL_MASK);
		else {
			size_t shift = GOT_DELTA_SIZE_SHIFT * i;
			*size |= (((**p) & GOT_DELTA_SIZE_VAL_MASK) << shift);
		}

		if (((**p) & GOT_DELTA_SIZE_MORE) == 0)
			break;
		i++;
		err = next_delta_byte(p, remain);
	} while (err == NULL);

	return err;
}

static const struct got_error *
parse_opcode(off_t *offset, size_t *len, const uint8_t **p, size_t *remain)
{
	const struct got_error *err = NULL;
	off_t o = 0;
	size_t l = 0;
	uint8_t opcode = **p;

	if (opcode & GOT_DELTA_COPY_OFF1) {
		err = next_delta_byte(p, remain);
		if (err)
			return err;
		o = (off_t)(**p);
	}
	if (opcode & GOT_DELTA_COPY_OFF2) {
		err = next_delta_byte(p, remain);
		if (err)
			return err;
		o |= ((off_t)(**p)) << 8;
	}
	if (opcode & GOT_DELTA_COPY_OFF3) {
		err = next_delta_byte(p, remain);
		if (err)
			return err;
		o |= ((off_t)(**p)) << 16;
	}
	if (opcode & GOT_DELTA_COPY_OFF4) {
		err = next_delta_byte(p, remain);
		if (err)
			return err;
		o |= ((off_t)(**p)) << 24;
	}

	if (opcode & GOT_DELTA_COPY_LEN1) {
		err = next_delta_byte(p, remain);
		if (err)
			return err;
		l = (off_t)(**p);
	}
	if (opcode & GOT_DELTA_COPY_LEN2) {
		err = next_delta_byte(p, remain);
		if (err)
			return err;
		l |= ((off_t)(**p)) << 8;
	}
	if (opcode & GOT_DELTA_COPY_LEN3) {
		err = next_delta_byte(p, remain);
		if (err)
			return err;
		l |= ((off_t)(**p)) << 16;
	}

	if (o == 0)
		o = GOT_DELTA_COPY_DEFAULT_OFF;
	if (l == 0)
		l = GOT_DELTA_COPY_DEFAULT_LEN;

	*offset = o;
	*len = l;
	return NULL;
}

static const struct got_error *
copy_from_base(FILE *base_file, off_t offset, size_t size, FILE *outfile)
{
	if (fseeko(base_file, offset, SEEK_SET) != 0)
		return got_error_from_errno("fseeko");

	while (size > 0) {
		uint8_t data[2048];
		size_t len = MIN(size, sizeof(data));
		size_t n;

		n = fread(data, len, 1, base_file);
		if (n != 1)
			return got_ferror(base_file, GOT_ERR_IO);

		n = fwrite(data, len, 1, outfile);
		if (n != 1)
			return got_ferror(outfile, GOT_ERR_IO);

		size -= len;
	}

	return NULL;
}

static const struct got_error *
copy_from_delta(const uint8_t **p, size_t *remain, size_t len, FILE *outfile)
{
	size_t n;

	if (*remain < len)
		return got_error_msg(GOT_ERR_BAD_DELTA,
		    "copy from beyond end of delta data");

	n = fwrite(*p, len, 1, outfile);
	if (n != 1)
		return got_ferror(outfile, GOT_ERR_IO);

	*p += len;
	*remain -= len;
	return NULL;
}

static const struct got_error *
parse_delta_sizes(uint64_t *base_size, uint64_t *result_size,
    const uint8_t **p, size_t *remain)
{
	const struct got_error *err;

	/* Read the two size fields at the beginning of the stream. */
	err = parse_size(base_size, p, remain);
	if (err)
		return err;
	err = next_delta_byte(p, remain);
	if (err)
		return err;
	err = parse_size(result_size, p, remain);
	if (err)
		return err;

	return NULL;
}

const struct got_error *
got_delta_get_sizes(uint64_t *base_size, uint64_t *result_size,
    const uint8_t *delta_buf, size_t delta_len)
{
	size_t remain;
	const uint8_t *p;

	if (delta_len < GOT_DELTA_STREAM_LENGTH_MIN)
		return got_error_msg(GOT_ERR_BAD_DELTA, "delta too small");

	p = delta_buf;
	remain = delta_len;
	return parse_delta_sizes(base_size, result_size, &p, &remain);
}

const struct got_error *
got_delta_apply_in_mem(uint8_t *base_buf, size_t base_bufsz,
    const uint8_t *delta_buf, size_t delta_len, uint8_t *outbuf,
    size_t *outsize, size_t maxoutsize)
{
	const struct got_error *err = NULL;
	uint64_t base_size, result_size;
	size_t remain;
	const uint8_t *p;

	*outsize= 0;

	if (delta_len < GOT_DELTA_STREAM_LENGTH_MIN)
		return got_error_msg(GOT_ERR_BAD_DELTA, "delta too small");

	p = delta_buf;
	remain = delta_len;
	err = parse_delta_sizes(&base_size, &result_size, &p, &remain);
	if (err)
		return err;

	/* Decode and execute copy instructions from the delta stream. */
	err = next_delta_byte(&p, &remain);
	while (err == NULL && remain > 0) {
		if (*p & GOT_DELTA_BASE_COPY) {
			off_t offset = 0;
			size_t len = 0;
			err = parse_opcode(&offset, &len, &p, &remain);
			if (err)
				break;
			if (SIZE_MAX - offset < len || offset + len < 0 ||
			    base_bufsz < offset + len ||
			    *outsize + len > maxoutsize)
				return got_error_msg(GOT_ERR_BAD_DELTA,
				    "bad delta copy length");
			memcpy(outbuf + *outsize, base_buf + offset, len);
			if (err == NULL) {
				*outsize += len;
				if (remain > 0) {
					p++;
					remain--;
				}
			}
		} else {
			size_t len = (size_t)*p;
			if (len == 0) {
				err = got_error_msg(GOT_ERR_BAD_DELTA,
				    "zero length delta");
				break;
			}
			err = next_delta_byte(&p, &remain);
			if (err)
				break;
			if (remain < len || SIZE_MAX - *outsize < len ||
			    *outsize + len > maxoutsize)
				return got_error_msg(GOT_ERR_BAD_DELTA,
				    "bad delta copy length");
			memcpy(outbuf + *outsize, p, len);
			p += len;
			remain -= len;
			*outsize += len;
		}
	}

	if (*outsize != result_size)
		err = got_error_msg(GOT_ERR_BAD_DELTA,
		    "delta application result size mismatch");
	return err;
}

const struct got_error *
got_delta_apply(FILE *base_file, const uint8_t *delta_buf,
    size_t delta_len, FILE *outfile, size_t *outsize)
{
	const struct got_error *err = NULL;
	uint64_t base_size, result_size;
	size_t remain = 0;
	const uint8_t *p;
	FILE *memstream = NULL;
	char *memstream_buf = NULL;
	size_t memstream_size = 0;

	*outsize = 0;

	if (delta_len < GOT_DELTA_STREAM_LENGTH_MIN)
		return got_error_msg(GOT_ERR_BAD_DELTA, "delta too small");

	p = delta_buf;
	remain = delta_len;
	err = parse_delta_sizes(&base_size, &result_size, &p, &remain);
	if (err)
		return err;

	if (result_size < GOT_DELTA_RESULT_SIZE_CACHED_MAX)
		memstream = open_memstream(&memstream_buf, &memstream_size);

	/* Decode and execute copy instructions from the delta stream. */
	err = next_delta_byte(&p, &remain);
	while (err == NULL && remain > 0) {
		if (*p & GOT_DELTA_BASE_COPY) {
			off_t offset = 0;
			size_t len = 0;
			err = parse_opcode(&offset, &len, &p, &remain);
			if (err)
				break;
			err = copy_from_base(base_file, offset, len,
			    memstream ? memstream : outfile);
			if (err == NULL) {
				*outsize += len;
				if (remain > 0) {
					p++;
					remain--;
				}
			}
		} else {
			size_t len = (size_t)*p;
			if (len == 0) {
				err = got_error_msg(GOT_ERR_BAD_DELTA,
				    "zero length delta");
				break;
			}
			err = next_delta_byte(&p, &remain);
			if (err)
				break;
			err = copy_from_delta(&p, &remain, len,
			    memstream ? memstream : outfile);
			if (err == NULL)
				*outsize += len;
		}
	}

	if (*outsize != result_size)
		err = got_error_msg(GOT_ERR_BAD_DELTA,
		    "delta application result size mismatch");

	if (memstream != NULL) {
		if (fclose(memstream) == EOF)
			err = got_error_from_errno("fclose");
		if (err == NULL) {
			size_t n;
			n = fwrite(memstream_buf, 1, memstream_size, outfile);
			if (n != memstream_size)
				err = got_ferror(outfile, GOT_ERR_IO);
		}
		free(memstream_buf);
	}
	if (err == NULL)
		rewind(outfile);
	return err;
}
