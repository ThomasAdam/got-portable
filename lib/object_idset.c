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
#include "got_lib_zbuf.h"
#include "got_lib_object.h"
#include "got_lib_object_idset.h"

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

struct got_object_idset_element {
	TAILQ_ENTRY(got_object_idset_element) entry;
	struct got_object_id id;
	void *data;	/* API user data */
};

struct got_object_idset {
	/*
	 * A set is implemented as a collection of 256 lists.
	 * The value of the first byte of an object ID determines
	 * which of these lists an object ID is stored in.
	 */
	TAILQ_HEAD(, got_object_idset_element) entries[0xff + 1];
	int nelem;
#define GOT_OBJECT_IDSET_MAX_ELEM INT_MAX
};

struct got_object_idset *
got_object_idset_alloc(void)
{
	struct got_object_idset *set;
	int i;

	set = calloc(1, sizeof(*set));
	if (set == NULL)
		return NULL;

	for (i = 0; i < nitems(set->entries); i++)
		TAILQ_INIT(&set->entries[i]);

	return set;
}

void
got_object_idset_free(struct got_object_idset *set)
{
	struct got_object_idset_element *entry;
	int i;

	for (i = 0; i < nitems(set->entries); i++) {
		while (!TAILQ_EMPTY(&set->entries[i])) {
			entry = TAILQ_FIRST(&set->entries[i]);
			TAILQ_REMOVE(&set->entries[i], entry, entry);
			/* User data should be freed by caller. */
			free(entry);
		}
	}
	free(set);
}

const struct got_error *
got_object_idset_add(void **existing_data,
    struct got_object_idset *set, struct got_object_id *id, void *data)
{
	struct got_object_idset_element *new, *entry;
	uint8_t i = id->sha1[0];

	if (existing_data)
		*existing_data = NULL;

	if (set->nelem >= GOT_OBJECT_IDSET_MAX_ELEM)
		return got_error(GOT_ERR_NO_SPACE);

	new = calloc(1, sizeof(*new));
	if (new == NULL)
		return got_error_from_errno();

	memcpy(&new->id, id, sizeof(new->id));
	new->data = data;

	if (TAILQ_EMPTY(&set->entries[i])) {
		TAILQ_INSERT_HEAD(&set->entries[i], new, entry);
		set->nelem++;
		return NULL;
	}

	/*
	 * Keep the list sorted by ID so that iterations of
	 * the set occur in a predictable order.
	 */
	TAILQ_FOREACH(entry, &set->entries[i], entry) {
		int cmp = got_object_id_cmp(&new->id, &entry->id);
		struct got_object_idset_element *next;

		if (cmp == 0) {
			free(new);
			if (existing_data)
				*existing_data = entry->data;
			return got_error(GOT_ERR_OBJ_EXISTS);
		} else if (cmp < 0) {
			TAILQ_INSERT_BEFORE(entry, new, entry);
			set->nelem++;
			return NULL;
		}

		next = TAILQ_NEXT(entry, entry);
		if (next == NULL) {
			TAILQ_INSERT_AFTER(&set->entries[i], entry, new, entry);
			set->nelem++;
			return NULL;
		} else if (got_object_id_cmp(&new->id, &next->id) > 0) {
			TAILQ_INSERT_BEFORE(next, new, entry);
			set->nelem++;
			return NULL;
		}
	}

	return got_error(GOT_ERR_BAD_OBJ_ID); /* should not get here */
}

void *
got_object_idset_get(struct got_object_idset *set, struct got_object_id *id)
{
	struct got_object_idset_element *entry;
	uint8_t i = id->sha1[0];

	TAILQ_FOREACH(entry, &set->entries[i], entry) {
		if (got_object_id_cmp(&entry->id, id) == 0)
			return entry->data;
	}

	return NULL;
}

const struct got_error *
got_object_idset_remove(void **data, struct got_object_idset *set,
    struct got_object_id *id)
{
	struct got_object_idset_element *entry, *tmp;
	uint8_t i = id->sha1[0];

	if (set->nelem == 0)
		return got_error(GOT_ERR_NO_OBJ);

	TAILQ_FOREACH_SAFE(entry, &set->entries[i], entry, tmp) {
		if (got_object_id_cmp(&entry->id, id) == 0) {
			TAILQ_REMOVE(&set->entries[i], entry, entry);
			if (data)
				*data = entry->data;
			free(entry);
			set->nelem--;
			return NULL;
		}
	}

	return got_error(GOT_ERR_NO_OBJ);
}

const struct got_error *
got_object_idset_remove_random(void **data, struct got_object_idset *set)
{
	struct got_object_idset_element *entry, *tmp;
	int i, n;

	if (data)
		*data = NULL;

	if (set->nelem == 0)
		return got_error(GOT_ERR_NO_OBJ);

	n = arc4random_uniform(set->nelem);
	for (i = 0; i < nitems(set->entries); i++) {
		TAILQ_FOREACH_SAFE(entry, &set->entries[i], entry, tmp) {
			if (--n == 0) {
				TAILQ_REMOVE(&set->entries[i], entry, entry);
				if (data)
					*data = entry->data;
				free(entry);
				set->nelem--;
				return NULL;
			}
		}

	}

	return got_error(GOT_ERR_NO_OBJ);
}

int
got_object_idset_contains(struct got_object_idset *set,
    struct got_object_id *id)
{
	struct got_object_idset_element *entry;
	uint8_t i = id->sha1[0];

	TAILQ_FOREACH(entry, &set->entries[i], entry) {
		if (got_object_id_cmp(&entry->id, id) == 0)
			return 1;
	}

	return 0;
}

void got_object_idset_for_each(struct got_object_idset *set,
    void (*cb)(struct got_object_id *, void *, void *), void *arg)
{
	struct got_object_idset_element *entry;
	int i;

	for (i = 0; i < nitems(set->entries); i++) {
		TAILQ_FOREACH(entry, &set->entries[i], entry)
			cb(&entry->id, entry->data, arg);
	}
}

int
got_object_idset_num_elements(struct got_object_idset *set)
{
	return set->nelem;
}
