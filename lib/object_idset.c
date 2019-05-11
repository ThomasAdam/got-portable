/*
 * Copyright (c) 2018, 2019 Stefan Sperling <stsp@openbsd.org>
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
#include <sys/tree.h>

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
#include "got_lib_object_idset.h"

struct got_object_idset_element {
	RB_ENTRY(got_object_idset_element)	entry;
	struct got_object_id id;
	void *data;	/* API user data */
};

RB_HEAD(got_object_idset_tree, got_object_idset_element);

static int
cmp_elements(const struct got_object_idset_element *e1,
    const struct got_object_idset_element *e2)
{
	return got_object_id_cmp(&e1->id, &e2->id);
}

RB_PROTOTYPE(got_object_idset_tree, got_object_idset_element, entry,
    cmp_elements);

struct got_object_idset {
	struct got_object_idset_tree entries;
	int totelem;
#define GOT_OBJECT_IDSET_MAX_ELEM INT_MAX
};

struct got_object_idset *
got_object_idset_alloc(void)
{
	struct got_object_idset *set;

	set = malloc(sizeof(*set));
	if (set == NULL)
		return NULL;

	RB_INIT(&set->entries);
	set->totelem = 0;

	return set;
}

void
got_object_idset_free(struct got_object_idset *set)
{
	struct got_object_idset_element *entry;

	while ((entry = RB_MIN(got_object_idset_tree, &set->entries))) {
		RB_REMOVE(got_object_idset_tree, &set->entries, entry);
		/* User data should be freed by caller. */
		free(entry);
	}

	free(set);
}

const struct got_error *
got_object_idset_add(struct got_object_idset *set, struct got_object_id *id,
    void *data)
{
	struct got_object_idset_element *new;

	if (set->totelem >= GOT_OBJECT_IDSET_MAX_ELEM)
		return got_error(GOT_ERR_NO_SPACE);

	new = malloc(sizeof(*new));
	if (new == NULL)
		return got_error_prefix_errno("malloc");

	memcpy(&new->id, id, sizeof(new->id));
	new->data = data;

	RB_INSERT(got_object_idset_tree, &set->entries, new);
	set->totelem++;
	return NULL;
}

static struct got_object_idset_element *
find_element(struct got_object_idset *set, struct got_object_id *id)
{
	struct got_object_idset_element *entry;

	entry = RB_ROOT(&set->entries);
	while (entry) {
		int cmp = got_object_id_cmp(id, &entry->id);
		if (cmp < 0)
			entry = RB_LEFT(entry, entry);
		else if (cmp > 0)
			entry = RB_RIGHT(entry, entry);
		else
			break;
	}

	return entry;
}

void *
got_object_idset_get(struct got_object_idset *set, struct got_object_id *id)
{
	struct got_object_idset_element *entry = find_element(set, id);
	return entry ? entry->data : NULL;
}

const struct got_error *
got_object_idset_remove(void **data, struct got_object_idset *set,
    struct got_object_id *id)
{
	struct got_object_idset_element *entry;

	if (data)
		*data = NULL;

	if (set->totelem == 0)
		return got_error(GOT_ERR_NO_OBJ);

	if (id == NULL)
		entry = RB_ROOT(&set->entries);
	else
		entry = find_element(set, id);
	if (entry == NULL)
		return got_error(GOT_ERR_NO_OBJ);

	RB_REMOVE(got_object_idset_tree, &set->entries, entry);
	if (data)
		*data = entry->data;
	free(entry);
	set->totelem--;
	return NULL;
}

int
got_object_idset_contains(struct got_object_idset *set,
    struct got_object_id *id)
{
	struct got_object_idset_element *entry = find_element(set, id);
	return entry ? 1 : 0;
}

const struct got_error *
got_object_idset_for_each(struct got_object_idset *set,
    const struct got_error *(*cb)(struct got_object_id *, void *, void *),
    void *arg)
{
	const struct got_error *err;
	struct got_object_idset_element *entry, *tmp;

	RB_FOREACH_SAFE(entry, got_object_idset_tree, &set->entries, tmp) {
		err = (*cb)(&entry->id, entry->data, arg);
		if (err)
			return err;
	}
	return NULL;
}

int
got_object_idset_num_elements(struct got_object_idset *set)
{
	return set->totelem;
}

RB_GENERATE(got_object_idset_tree, got_object_idset_element, entry,
    cmp_elements);
