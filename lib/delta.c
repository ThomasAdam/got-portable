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

struct got_delta_base *
got_delta_base_open(const char *path_packfile, int type, off_t offset,
    size_t delta_size)
{
	struct got_delta_base *base;

	base = calloc(1, sizeof(*base));
	if (base == NULL)
		return NULL;

	base->path_packfile = strdup(path_packfile);
	if (base->path_packfile == NULL) {
		free(base);
		return NULL;
	}
	base->type = type;
	base->offset = offset;
	base->delta_size = delta_size;
	return base;
}

void
got_delta_base_close(struct got_delta_base *base)
{
	free(base->path_packfile);
	free(base);

}

const struct got_error *
got_delta_chain_get_base_type(int *type, struct got_delta_chain *deltas)
{
	struct got_delta_base *base;
	int n = 0;

	/* Find the last base in the chain. It should be a plain object. */
	SIMPLEQ_FOREACH(base, &deltas->entries, entry) {
		n++;
		if (base->type == GOT_OBJ_TYPE_COMMIT ||
		    base->type == GOT_OBJ_TYPE_TREE ||
		    base->type == GOT_OBJ_TYPE_BLOB ||
		    base->type == GOT_OBJ_TYPE_TAG) {
			if (n != deltas->nentries)
				return got_error(GOT_ERR_BAD_DELTA_CHAIN);
			*type = base->type;
			return NULL;
		}
	}

	return got_error(GOT_ERR_BAD_DELTA_CHAIN);
}

const struct got_error *
got_delta_apply(struct got_repository *repo, FILE *infile, size_t size,
    struct got_object *base_obj, FILE *outfile)
{
	return got_error(GOT_ERR_NOT_IMPL);
}
