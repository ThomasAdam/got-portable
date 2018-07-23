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
#include "got_lib_object_idcache.h"

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

struct got_object_idcache_element {
	TAILQ_ENTRY(got_object_idcache_element) entry;
	struct got_object_id id;
	void *data;	/* API user data */
};

TAILQ_HEAD(got_object_idcache_head, got_object_idcache_element);

struct got_object_idcache {
	struct got_object_idcache_head entries;
	int nelem;
	int maxelem;
};

struct got_object_idcache *
got_object_idcache_alloc(int maxelem)
{
	struct got_object_idcache *cache;

	cache = calloc(1, sizeof(*cache));
	if (cache == NULL)
		return NULL;

	TAILQ_INIT(&cache->entries);
	cache->maxelem = maxelem;
	return cache;
}

void
got_object_idcache_free(struct got_object_idcache *cache)
{
	struct got_object_idcache_element *entry;

	while (!TAILQ_EMPTY(&cache->entries)) {
		entry = TAILQ_FIRST(&cache->entries);
		TAILQ_REMOVE(&cache->entries, entry, entry);
		/* User data should be freed by caller. */
		free(entry);
	}
	free(cache);
}

const struct got_error *
got_object_idcache_add(struct got_object_idcache *cache,
    struct got_object_id *id, void *data)
{
	struct got_object_idcache_element *entry;

	if (cache->nelem >= cache->maxelem)
		return got_error(GOT_ERR_NO_SPACE);

	entry = calloc(1, sizeof(*entry));
	if (entry == NULL)
		return got_error_from_errno();

	memcpy(&entry->id, id, sizeof(entry->id));
	entry->data = data;

	TAILQ_INSERT_HEAD(&cache->entries, entry, entry);
	cache->nelem++;
	return NULL;
}

void *
got_object_idcache_get(struct got_object_idcache *cache, struct got_object_id *id)
{
	struct got_object_idcache_element *entry;

	TAILQ_FOREACH(entry, &cache->entries, entry) {
		if (got_object_id_cmp(&entry->id, id) != 0)
			continue;
		if (entry != TAILQ_FIRST(&cache->entries)) {
			TAILQ_REMOVE(&cache->entries, entry, entry);
			TAILQ_INSERT_HEAD(&cache->entries, entry, entry);
		}
		return entry->data;
	}

	return NULL;
}

const struct got_error *
got_object_idcache_remove_least_used(void **data, struct got_object_idcache *cache)
{
	struct got_object_idcache_element *entry;

	if (data)
		*data = NULL;

	if (cache->nelem == 0)
		return got_error(GOT_ERR_NO_OBJ);

	entry = TAILQ_LAST(&cache->entries, got_object_idcache_head);
	TAILQ_REMOVE(&cache->entries, entry, entry);
	if (data)
		*data = entry->data;
	free(entry);
	cache->nelem--;
	return NULL;
}

int
got_object_idcache_contains(struct got_object_idcache *cache,
    struct got_object_id *id)
{
	struct got_object_idcache_element *entry;

	TAILQ_FOREACH(entry, &cache->entries, entry) {
		if (got_object_id_cmp(&entry->id, id) == 0)
			return 1;
	}

	return 0;
}

void got_object_idcache_for_each(struct got_object_idcache *cache,
    void (*cb)(struct got_object_id *, void *, void *), void *arg)
{
	struct got_object_idcache_element *entry;

	TAILQ_FOREACH(entry, &cache->entries, entry)
		cb(&entry->id, entry->data, arg);
}

int
got_object_idcache_num_elements(struct got_object_idcache *set)
{
	return set->nelem;
}
