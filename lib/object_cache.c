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
#include <sys/resource.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <sha1.h>
#include <sha2.h>
#include <zlib.h>

#include "got_error.h"
#include "got_object.h"

#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_object_idset.h"
#include "got_lib_object_cache.h"

/*
 * XXX This should be reworked to track cache size and usage in bytes,
 * rather than tracking N elements capped to a maximum element size.
 */
#define GOT_OBJECT_CACHE_SIZE_OBJ	256
#define GOT_OBJECT_CACHE_SIZE_TREE	256
#define GOT_OBJECT_CACHE_SIZE_COMMIT	64
#define GOT_OBJECT_CACHE_SIZE_TAG	256
#define GOT_OBJECT_CACHE_SIZE_RAW	16
#define GOT_OBJECT_CACHE_MAX_ELEM_SIZE	1048576	/* 1 MB */

const struct got_error *
got_object_cache_init(struct got_object_cache *cache,
    enum got_object_cache_type type)
{
	struct rlimit rl;

	memset(cache, 0, sizeof(*cache));

	cache->idset = got_object_idset_alloc();
	if (cache->idset == NULL)
		return got_error_from_errno("got_object_idset_alloc");

	cache->type = type;
	switch (type) {
	case GOT_OBJECT_CACHE_TYPE_OBJ:
		cache->size = GOT_OBJECT_CACHE_SIZE_OBJ;
		break;
	case GOT_OBJECT_CACHE_TYPE_TREE:
		cache->size = GOT_OBJECT_CACHE_SIZE_TREE;
		break;
	case GOT_OBJECT_CACHE_TYPE_COMMIT:
		cache->size = GOT_OBJECT_CACHE_SIZE_COMMIT;
		break;
	case GOT_OBJECT_CACHE_TYPE_TAG:
		cache->size = GOT_OBJECT_CACHE_SIZE_TAG;
		break;
	case GOT_OBJECT_CACHE_TYPE_RAW:
		if (getrlimit(RLIMIT_NOFILE, &rl) == -1)
			return got_error_from_errno("getrlimit");
		cache->size = GOT_OBJECT_CACHE_SIZE_RAW;
		if (cache->size > rl.rlim_cur / 16)
			cache->size = rl.rlim_cur / 16;
		break;
	}
	return NULL;
}

static size_t
get_size_obj(struct got_object *obj)
{
	size_t size = sizeof(*obj);
	struct got_delta *delta;

	if ((obj->flags & GOT_OBJ_FLAG_DELTIFIED) == 0)
		return size;

	STAILQ_FOREACH(delta, &obj->deltas.entries, entry) {
		if (SIZE_MAX - sizeof(*delta) < size)
			return SIZE_MAX;
		size += sizeof(*delta);
	}

	return size;
}

static size_t
get_size_tree(struct got_tree_object *tree)
{
	size_t size = sizeof(*tree);

	size += sizeof(struct got_tree_entry) * tree->nentries;
	return size;
}

static size_t
get_size_commit(struct got_commit_object *commit)
{
	size_t size = sizeof(*commit);
	struct got_object_qid *qid;

	size += sizeof(*commit->tree_id);
	size += strlen(commit->author);
	size += strlen(commit->committer);
	size += strlen(commit->logmsg);

	STAILQ_FOREACH(qid, &commit->parent_ids, entry)
		size += sizeof(*qid) + sizeof(qid->id);

	return size;
}

static size_t
get_size_tag(struct got_tag_object *tag)
{
	size_t size = sizeof(*tag);

	size += strlen(tag->tag);
	size += strlen(tag->tagger);
	size += strlen(tag->tagmsg);

	return size;
}

static size_t
get_size_raw(struct got_raw_object *raw)
{
	return sizeof(*raw);
}

const struct got_error *
got_object_cache_add(struct got_object_cache *cache, struct got_object_id *id,
    void *item)
{
	const struct got_error *err = NULL;
	struct got_object_cache_entry *ce;
	int nelem;
	size_t size;

	switch (cache->type) {
	case GOT_OBJECT_CACHE_TYPE_OBJ:
		size = get_size_obj((struct got_object *)item);
		break;
	case GOT_OBJECT_CACHE_TYPE_TREE:
		size = get_size_tree((struct got_tree_object *)item);
		break;
	case GOT_OBJECT_CACHE_TYPE_COMMIT:
		size = get_size_commit((struct got_commit_object *)item);
		break;
	case GOT_OBJECT_CACHE_TYPE_TAG:
		size = get_size_tag((struct got_tag_object *)item);
		break;
	case GOT_OBJECT_CACHE_TYPE_RAW:
		size = get_size_raw((struct got_raw_object *)item);
		break;
	default:
		return got_error(GOT_ERR_OBJ_TYPE);
	}

	if (size > GOT_OBJECT_CACHE_MAX_ELEM_SIZE) {
#ifdef GOT_OBJ_CACHE_DEBUG
		char *id_str;
		if (got_object_id_str(&id_str, id) != NULL)
			return got_error_from_errno("got_object_id_str");
		fprintf(stderr, "%s: not caching ", getprogname());
		switch (cache->type) {
		case GOT_OBJECT_CACHE_TYPE_OBJ:
			fprintf(stderr, "object");
			break;
		case GOT_OBJECT_CACHE_TYPE_TREE:
			fprintf(stderr, "tree");
			break;
		case GOT_OBJECT_CACHE_TYPE_COMMIT:
			fprintf(stderr, "commit");
			break;
		case GOT_OBJECT_CACHE_TYPE_TAG:
			fprintf(stderr, "tag");
			break;
		case GOT_OBJECT_CACHE_TYPE_RAW:
			fprintf(stderr, "raw");
			break;
		}
		fprintf(stderr, " %s (%zd bytes; %zd MB)\n", id_str, size,
		    size/1024/1024);
		free(id_str);
#endif
		cache->cache_toolarge++;
		return got_error(GOT_ERR_OBJ_TOO_LARGE);
	}

	nelem = got_object_idset_num_elements(cache->idset);
	if (nelem >= cache->size) {
		err = got_object_idset_remove((void **)&ce,
		    cache->idset, NULL);
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
		case GOT_OBJECT_CACHE_TYPE_TAG:
			got_object_tag_close(ce->data.tag);
			break;
		case GOT_OBJECT_CACHE_TYPE_RAW:
			got_object_raw_close(ce->data.raw);
			break;
		}
		memset(ce, 0, sizeof(*ce));
		cache->cache_evict++;
	} else {
		ce = malloc(sizeof(*ce));
		if (ce == NULL)
			return got_error_from_errno("malloc");
	}

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
	case GOT_OBJECT_CACHE_TYPE_TAG:
		ce->data.tag = (struct got_tag_object *)item;
		break;
	case GOT_OBJECT_CACHE_TYPE_RAW:
		ce->data.raw = (struct got_raw_object *)item;
		break;
	}

	err = got_object_idset_add(cache->idset, id, ce);
	if (err)
		free(ce);
	else if (size > cache->max_cached_size)
		cache->max_cached_size = size;
	return err;
}

void *
got_object_cache_get(struct got_object_cache *cache, struct got_object_id *id)
{
	struct got_object_cache_entry *ce;

	cache->cache_searches++;
	ce = got_object_idset_get(cache->idset, id);
	if (ce) {
		cache->cache_hit++;
		switch (cache->type) {
		case GOT_OBJECT_CACHE_TYPE_OBJ:
			return ce->data.obj;
		case GOT_OBJECT_CACHE_TYPE_TREE:
			return ce->data.tree;
		case GOT_OBJECT_CACHE_TYPE_COMMIT:
			return ce->data.commit;
		case GOT_OBJECT_CACHE_TYPE_TAG:
			return ce->data.tag;
		case GOT_OBJECT_CACHE_TYPE_RAW:
			return ce->data.raw;
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
	    "%d missed, %d evicted, %d too large, max cached %zd bytes\n",
	    getprogname(), name,
	    cache->idset ? got_object_idset_num_elements(cache->idset) : -1,
	    cache->cache_searches, cache->cache_hit,
	    cache->cache_miss, cache->cache_evict, cache->cache_toolarge,
	    cache->max_cached_size);
}

static const struct got_error *
check_refcount(struct got_object_id *id, void *data, void *arg)
{
	struct got_object_cache *cache = arg;
	struct got_object_cache_entry *ce = data;
	struct got_object *obj;
	struct got_tree_object *tree;
	struct got_commit_object *commit;
	struct got_tag_object *tag;
	struct got_raw_object *raw;
	char *id_str;

	if (got_object_id_str(&id_str, id) != NULL)
		return NULL;

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
	case GOT_OBJECT_CACHE_TYPE_TAG:
		tag = ce->data.tag;
		if (tag->refcnt == 1)
			break;
		fprintf(stderr, "tag %s has %d unclaimed references\n",
		    id_str, tag->refcnt - 1);
		break;
	case GOT_OBJECT_CACHE_TYPE_RAW:
		raw = ce->data.raw;
		if (raw->refcnt == 1)
			break;
		fprintf(stderr, "raw %s has %d unclaimed references\n",
		    id_str, raw->refcnt - 1);
		break;
	}
	free(id_str);
	return NULL;
}
#endif

static const struct got_error *
free_entry(struct got_object_id *id, void *data, void *arg)
{
	struct got_object_cache *cache = arg;
	struct got_object_cache_entry *ce = data;

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
	case GOT_OBJECT_CACHE_TYPE_TAG:
		got_object_tag_close(ce->data.tag);
		break;
	case GOT_OBJECT_CACHE_TYPE_RAW:
		got_object_raw_close(ce->data.raw);
		break;
	}

	free(ce);

	return NULL;
}

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
	case GOT_OBJECT_CACHE_TYPE_TAG:
		print_cache_stats(cache, "tag");
		break;
	case GOT_OBJECT_CACHE_TYPE_RAW:
		print_cache_stats(cache, "raw");
		break;
	}

	if (cache->idset)
		got_object_idset_for_each(cache->idset, check_refcount, cache);
#endif

	if (cache->idset) {
		got_object_idset_for_each(cache->idset, free_entry, cache);
		got_object_idset_free(cache->idset);
		cache->idset = NULL;
	}
	cache->size = 0;
}
