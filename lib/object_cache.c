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

#include <sys/time.h>
#include <sys/queue.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sha1.h>
#include <zlib.h>

#include "got_error.h"
#include "got_object.h"

#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_object_idcache.h"
#include "got_lib_object_cache.h"

#define GOT_OBJECT_CACHE_SIZE_OBJ		1024
#define GOT_OBJECT_CACHE_SIZE_TREE		2048
#define GOT_OBJECT_CACHE_SIZE_COMMIT		512
#define GOT_OBJECT_CACHE_SIZE_MINI_COMMIT	512

const struct got_error *
got_object_cache_init(struct got_object_cache *cache,
    enum got_object_cache_type type)
{
	size_t size;

	switch (type) {
	case GOT_OBJECT_CACHE_TYPE_OBJ:
		size = GOT_OBJECT_CACHE_SIZE_OBJ;
		break;
	case GOT_OBJECT_CACHE_TYPE_TREE:
		size = GOT_OBJECT_CACHE_SIZE_TREE;
		break;
	case GOT_OBJECT_CACHE_TYPE_COMMIT:
		size = GOT_OBJECT_CACHE_SIZE_COMMIT;
		break;
	case GOT_OBJECT_CACHE_TYPE_MINI_COMMIT:
		size = GOT_OBJECT_CACHE_SIZE_MINI_COMMIT;
		break;
	}

	cache->idcache = got_object_idcache_alloc(size);
	if (cache->idcache == NULL)
		return got_error_from_errno();
	cache->type = type;
	cache->size = size;
	return NULL;
}

const struct got_error *
got_object_cache_add(struct got_object_cache *cache, struct got_object_id *id, void *item)
{
	const struct got_error *err = NULL;
	struct got_object_cache_entry *ce;
	int nelem;

	nelem = got_object_idcache_num_elements(cache->idcache);
	if (nelem >= cache->size) {
		err = got_object_idcache_remove_least_used((void **)&ce,
		    cache->idcache);
		if (err)
			return err;
		switch (cache->type) {
		case GOT_OBJECT_CACHE_TYPE_OBJ:
			got_object_close(ce->data.obj);
			break;
		case GOT_OBJECT_CACHE_TYPE_TREE:
			got_object_tree_close(ce->data.tree);
			break;
		case GOT_OBJECT_CACHE_TYPE_COMMIT:
			got_object_commit_close(ce->data.commit);
			break;
		case GOT_OBJECT_CACHE_TYPE_MINI_COMMIT:
			got_object_mini_commit_close(ce->data.mini_commit);
			break;
		}
		free(ce);
		cache->cache_evict++;
	}

	ce = calloc(1, sizeof(*ce));
	if (ce == NULL)
		return got_error_from_errno();
	memcpy(&ce->id, id, sizeof(ce->id));
	switch (cache->type) {
	case GOT_OBJECT_CACHE_TYPE_OBJ:
		ce->data.obj = (struct got_object *)item;
		break;
	case GOT_OBJECT_CACHE_TYPE_TREE:
		ce->data.tree = (struct got_tree_object *)item;
		break;
	case GOT_OBJECT_CACHE_TYPE_COMMIT:
		ce->data.commit = (struct got_commit_object *)item;
		break;
	case GOT_OBJECT_CACHE_TYPE_MINI_COMMIT:
		ce->data.mini_commit = (struct got_commit_object_mini *)item;
		break;
	}

	err = got_object_idcache_add(cache->idcache, id, ce);
	if (err) {
		if (err->code == GOT_ERR_OBJ_EXISTS) {
			free(ce);
			err = NULL;
		}
	}
	return err;
}

void *
got_object_cache_get(struct got_object_cache *cache, struct got_object_id *id)
{
	struct got_object_cache_entry *ce;

	cache->cache_searches++;
	ce = got_object_idcache_get(cache->idcache, id);
	if (ce) {
		cache->cache_hit++;
		switch (cache->type) {
		case GOT_OBJECT_CACHE_TYPE_OBJ:
			return ce->data.obj;
		case GOT_OBJECT_CACHE_TYPE_TREE:
			return ce->data.tree;
		case GOT_OBJECT_CACHE_TYPE_COMMIT:
			return ce->data.commit;
		case GOT_OBJECT_CACHE_TYPE_MINI_COMMIT:
			return ce->data.mini_commit;
		}
	}

	cache->cache_miss++;
	return NULL;
}

#ifdef GOT_OBJ_CACHE_DEBUG
static void
print_cache_stats(struct got_object_cache *cache, const char *name)
{
	fprintf(stderr, "%s: %s cache: %d elements, %d searches, %d hits, "
	    "%d missed, %d evicted\n", getprogname(), name,
	    got_object_idcache_num_elements(cache->idcache),
	    cache->cache_searches, cache->cache_hit,
	    cache->cache_miss, cache->cache_evict);
}

void check_refcount(struct got_object_id *id, void *data, void *arg)
{
	struct got_object_cache *cache = arg;
	struct got_object_cache_entry *ce = data;
	struct got_object *obj;
	struct got_tree_object *tree;
	struct got_commit_object *commit;
	struct got_commit_object_mini *mini_commit;
	char *id_str;

	if (got_object_id_str(&id_str, id) != NULL)
		return;

	switch (cache->type) {
	case GOT_OBJECT_CACHE_TYPE_OBJ:
		obj = ce->data.obj;
		if (obj->refcnt == 1)
			break;
		fprintf(stderr, "object %s has %d unclaimed references\n",
		    id_str, obj->refcnt - 1);
		break;
	case GOT_OBJECT_CACHE_TYPE_TREE:
		tree = ce->data.tree;
		if (tree->refcnt == 1)
			break;
		fprintf(stderr, "tree %s has %d unclaimed references\n",
		    id_str, tree->refcnt - 1);
		break;
	case GOT_OBJECT_CACHE_TYPE_COMMIT:
		commit = ce->data.commit;
		if (commit->refcnt == 1)
			break;
		fprintf(stderr, "commit %s has %d unclaimed references\n",
		    id_str, commit->refcnt - 1);
		break;
	case GOT_OBJECT_CACHE_TYPE_MINI_COMMIT:
		mini_commit = ce->data.mini_commit;
		if (mini_commit->refcnt == 1)
			break;
		fprintf(stderr, "commit %s has %d unclaimed references\n",
		    id_str, mini_commit->refcnt - 1);
		break;
	}
	free(id_str);
}
#endif

void
got_object_cache_close(struct got_object_cache *cache)
{
#ifdef GOT_OBJ_CACHE_DEBUG
	switch (cache->type) {
	case GOT_OBJECT_CACHE_TYPE_OBJ:
		print_cache_stats(cache, "object");
		break;
	case GOT_OBJECT_CACHE_TYPE_TREE:
		print_cache_stats(cache, "tree");
		break;
	case GOT_OBJECT_CACHE_TYPE_COMMIT:
		print_cache_stats(cache, "commit");
		break;
	case GOT_OBJECT_CACHE_TYPE_MINI_COMMIT:
		print_cache_stats(cache, "mini-commit");
		break;
	}

	got_object_idcache_for_each(cache->idcache, check_refcount, cache);
#endif

	if (cache->idcache) {
		got_object_idcache_free(cache->idcache);
		cache->idcache = NULL;
	}
	cache->size = 0;
}
