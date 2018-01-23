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

#include "delta.h"

struct got_delta *
got_delta_open(const char *path_packfile, int type, off_t offset,
    size_t size)
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
	delta->size = size;
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

const struct got_error *got_delta_apply(struct got_delta *delta,
    FILE *base_file, FILE *delta_file, FILE *outfile)
{
	return got_error(GOT_ERR_NOT_IMPL);
}
