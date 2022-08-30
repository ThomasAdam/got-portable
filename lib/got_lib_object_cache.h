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

enum got_object_cache_type {
	GOT_OBJECT_CACHE_TYPE_OBJ,
	GOT_OBJECT_CACHE_TYPE_TREE,
	GOT_OBJECT_CACHE_TYPE_COMMIT,
	GOT_OBJECT_CACHE_TYPE_TAG,
	GOT_OBJECT_CACHE_TYPE_RAW,
};

struct got_object_cache_entry {
	struct got_object_id id;
	union {
		struct got_object *obj;
		struct got_tree_object *tree;
		struct got_commit_object *commit;
		struct got_tag_object *tag;
		struct got_raw_object *raw;
	} data;
};

struct got_object_cache {
	enum got_object_cache_type type;
	struct got_object_idset *idset;
	size_t size;
	int cache_searches;
	int cache_hit;
	int cache_miss;
	int cache_evict;
	int cache_toolarge;
	size_t max_cached_size;
};

const struct got_error *got_object_cache_init(struct got_object_cache *,
    enum got_object_cache_type);
const struct got_error *got_object_cache_add(struct got_object_cache *,
    struct got_object_id *, void *);
void *got_object_cache_get(struct got_object_cache *, struct got_object_id *);
void got_object_cache_close(struct got_object_cache *);
