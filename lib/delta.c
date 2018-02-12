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
#include <zlib.h>
#include <sha1.h>

#include "got_error.h"
#include "got_repository.h"
#include "got_object.h"

#include "got_delta_priv.h"
#include "got_path_priv.h"
#include "got_zb_priv.h"

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

struct got_delta *
got_delta_open(const char *path_packfile, off_t offset, size_t tslen,
    int type, size_t size, off_t data_offset)
{
	struct got_delta *delta;

	delta = calloc(1, sizeof(*delta));
	if (delta == NULL)
		return NULL;

	delta->path_packfile = strdup(path_packfile);
	if (delta->path_packfile == NULL) {
		free(delta);
		return NULL;
	}
	delta->type = type;
	delta->offset = offset;
	delta->tslen = tslen;
	delta->size = size;
	delta->data_offset = data_offset;
	return delta;
}

void
got_delta_close(struct got_delta *delta)
{
	free(delta->path_packfile);
	free(delta);

}

const struct got_error *
got_delta_chain_get_base_type(int *type, struct got_delta_chain *deltas)
{
	struct got_delta *delta;

	/* The first delta in the chain should represent the base object. */
	delta = SIMPLEQ_FIRST(&deltas->entries);
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
		return got_error(GOT_ERR_BAD_DELTA);
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
		return got_error_from_errno();

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
		return got_error(GOT_ERR_BAD_DELTA);

	n = fwrite(*p, len, 1, outfile);
	if (n != 1)
		return got_ferror(outfile, GOT_ERR_IO);

	*p += len;
	*remain -= len;
	return NULL;
}

const struct got_error *
got_delta_apply(FILE *base_file, const uint8_t *delta_buf,
    size_t delta_len, FILE *outfile)
{
	const struct got_error *err = NULL;
	uint64_t base_size, result_size;
	size_t remain, outsize = 0;
	const uint8_t *p;

	if (delta_len < GOT_DELTA_STREAM_LENGTH_MIN)
		return got_error(GOT_ERR_BAD_DELTA);

	p = delta_buf;
	remain = delta_len;

	/* Read the two size fields at the beginning of the stream. */
	err = parse_size(&base_size, &p, &remain);
	if (err)
		return err;
	err = next_delta_byte(&p, &remain);
	if (err)
		return err;
	err = parse_size(&result_size, &p, &remain);
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
			err = copy_from_base(base_file, offset, len, outfile);
			if (err == NULL) {
				outsize += len;
				if (remain > 0) {
					p++;
					remain--;
				}
			}
		} else {
			size_t len = (size_t)*p;
			if (len == 0) {
				err = got_error(GOT_ERR_BAD_DELTA);
				break;
			}
			err = next_delta_byte(&p, &remain);
			if (err)
				break;
			err = copy_from_delta(&p, &remain, len, outfile);
			if (err == NULL)
				outsize += len;
		}
	}

	if (outsize != result_size)
		err = got_error(GOT_ERR_BAD_DELTA);

	if (err == NULL)
		rewind(outfile);
	return err;
}
