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

#include <stdlib.h>
#include <string.h>
#include <sha1.h>
#include <stdio.h>
#include <zlib.h>
#include <limits.h>
#include <time.h>

#include "got_object.h"
#include "got_error.h"

#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_delta_cache.h"

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

struct got_delta_cache_element {
	TAILQ_ENTRY(got_delta_cache_element) entry;
	off_t delta_data_offset;
	uint8_t *delta_data;
	size_t delta_len;
};

TAILQ_HEAD(got_delta_cache_head, got_delta_cache_element);

struct got_delta_cache {
	struct got_delta_cache_head entries;
	int nelem;
	int maxelem;
	size_t maxelemsize;
};

struct got_delta_cache *
got_delta_cache_alloc(int maxelem, size_t maxelemsize)
{
	struct got_delta_cache *cache;

	cache = calloc(1, sizeof(*cache));
	if (cache == NULL)
		return NULL;

	TAILQ_INIT(&cache->entries);
	cache->maxelem = maxelem;
	cache->maxelemsize = maxelemsize;
	return cache;
}

void
got_delta_cache_free(struct got_delta_cache *cache)
{
	struct got_delta_cache_element *entry;

	while (!TAILQ_EMPTY(&cache->entries)) {
		entry = TAILQ_FIRST(&cache->entries);
		TAILQ_REMOVE(&cache->entries, entry, entry);
		free(entry->delta_data);
		free(entry);
	}
	free(cache);
}

static void
remove_least_used_element(struct got_delta_cache *cache)
{
	struct got_delta_cache_element *entry;

	if (cache->nelem == 0)
		return;

	entry = TAILQ_LAST(&cache->entries, got_delta_cache_head);
	TAILQ_REMOVE(&cache->entries, entry, entry);
	free(entry->delta_data);
	free(entry);
	cache->nelem--;
}


const struct got_error *
got_delta_cache_add(struct got_delta_cache *cache,
    off_t delta_data_offset, uint8_t *delta_data, size_t delta_len)
{
	struct got_delta_cache_element *entry;

	if (delta_len > cache->maxelemsize)
		return got_error(GOT_ERR_NO_SPACE);

	if (cache->nelem >= cache->maxelem)
		remove_least_used_element(cache);

	entry = calloc(1, sizeof(*entry));
	if (entry == NULL)
		return got_error_from_errno("calloc");

	entry->delta_data_offset = delta_data_offset;
	entry->delta_data = delta_data;
	entry->delta_len = delta_len;

	TAILQ_INSERT_HEAD(&cache->entries, entry, entry);
	cache->nelem++;
	return NULL;
}

void
got_delta_cache_get(uint8_t **delta_data, size_t *delta_len,
    struct got_delta_cache *cache, off_t delta_data_offset)
{
	struct got_delta_cache_element *entry;

	*delta_data = NULL;
	*delta_len = 0;
	TAILQ_FOREACH(entry, &cache->entries, entry) {
		if (entry->delta_data_offset != delta_data_offset)
			continue;
		if (entry != TAILQ_FIRST(&cache->entries)) {
			TAILQ_REMOVE(&cache->entries, entry, entry);
			TAILQ_INSERT_HEAD(&cache->entries, entry, entry);
		}
		*delta_data = entry->delta_data;
		*delta_len = entry->delta_len;
		return;
	}
}
