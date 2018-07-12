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
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <sha1.h>
#include <zlib.h>

#include "got_object.h"

#include "got_error.h"
#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_diffoffset.h"

/*
 * A line offset between an old file and a new file, derived from diff chunk
 * header info @@ -old_lineno,old_length +new_lineno,new_length @@ in a diff
 * with zero context lines (as in diff -U0 old-file new-file).
 */
struct got_diffoffset_chunk {
	int lineno;	/* first line which has shifted */
	int offset;	/* applies to subsequent lines until next chunk */
	SIMPLEQ_ENTRY(got_diffoffset_chunk) entry;
};

static struct got_diffoffset_chunk *
alloc_chunk(int lineno, int offset)
{
	struct got_diffoffset_chunk *chunk;

	chunk = calloc(1, sizeof(*chunk));
	if (chunk == NULL)
		return NULL;

	chunk->lineno = lineno;
	chunk->offset = offset;

	return chunk;
}

const struct got_error *
got_diffoffset_alloc(struct got_diffoffset_chunks **chunks)
{
	const struct got_error *err = NULL;
	struct got_diffoffset_chunk *first;

	first = alloc_chunk(0, 0);
	if (first == NULL)
		return got_error_from_errno();

	*chunks = calloc(1, sizeof(**chunks));
	if (*chunks == NULL) {
		err = got_error_from_errno();
		free(first);
		return err;
	}

	SIMPLEQ_INIT(*chunks);
	SIMPLEQ_INSERT_HEAD(*chunks, first, entry);

	return NULL;
}

void
got_diffoffset_free(struct got_diffoffset_chunks *chunks)
{
	struct got_diffoffset_chunk *chunk;

	while (!SIMPLEQ_EMPTY(chunks)) {
		chunk = SIMPLEQ_FIRST(chunks);
		SIMPLEQ_REMOVE_HEAD(chunks, entry);
		free(chunk);
	}
	free(chunks);
}

const struct got_error *
got_diffoffset_add(struct got_diffoffset_chunks *chunks,
    int old_lineno, int old_length, int new_lineno, int new_length)
{
	struct got_diffoffset_chunk *chunk1, *chunk2;

	chunk1 = alloc_chunk(old_lineno, new_lineno - old_lineno);
	if (chunk1 == NULL)
		return got_error_from_errno();

	chunk2 = alloc_chunk(old_lineno + old_length,
	    new_lineno - old_lineno + new_length - old_length);
	if (chunk2 == NULL) {
		const struct got_error *err = got_error_from_errno();
		free(chunk1);
		return err;
	}

	SIMPLEQ_INSERT_TAIL(chunks, chunk1, entry);
	SIMPLEQ_INSERT_TAIL(chunks, chunk2, entry);
	return NULL;
}

int
got_diffoffset_get(struct got_diffoffset_chunks *chunks, int lineno)
{
	struct got_diffoffset_chunk *chunk, *prev;

	prev = SIMPLEQ_FIRST(chunks);
	SIMPLEQ_FOREACH(chunk, chunks, entry) {
		if (chunk->lineno > lineno)
			break;
		prev = chunk;
	}

	return lineno + prev->offset;
}
