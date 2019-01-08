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

#include <sys/tree.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>

#include "got_error.h"
#include "got_lib_path.h"
#include "got_lib_pathset.h"

struct got_pathset_element {
	RB_ENTRY(got_pathset_element)	entry;
	char *path;
	void *data;	/* API user data */
};

RB_HEAD(got_pathset_tree, got_pathset_element);

static int
cmp_elements(const struct got_pathset_element *e1,
    const struct got_pathset_element *e2)
{
	return got_compare_paths(e1->path, e2->path);
}

RB_PROTOTYPE(got_pathset_tree, got_pathset_element, entry, cmp_elements);

struct got_pathset {
	struct got_pathset_tree entries;
	int totelem;
#define GOT_PATHSET_MAX_ELEM INT_MAX
};

struct got_pathset *
got_pathset_alloc(void)
{
	struct got_pathset *set;

	set = malloc(sizeof(*set));
	if (set == NULL)
		return NULL;

	RB_INIT(&set->entries);
	set->totelem = 0;

	return set;
}

static void
free_element(struct got_pathset_element *entry)
{
	free(entry->path);
	free(entry);
}

void
got_pathset_free(struct got_pathset *set)
{
	struct got_pathset_element *entry;

	while ((entry = RB_MIN(got_pathset_tree, &set->entries))) {
		RB_REMOVE(got_pathset_tree, &set->entries, entry);
		/* User data should be freed by caller. */
		free_element(entry);
	}

	free(set);
}

const struct got_error *
got_pathset_add(struct got_pathset *set, const char *path, void *data)
{
	struct got_pathset_element *new;

	if (set->totelem >= GOT_PATHSET_MAX_ELEM)
		return got_error(GOT_ERR_NO_SPACE);

	new = malloc(sizeof(*new));
	if (new == NULL)
		return got_error_from_errno();

	new->path = strdup(path);
	if (new->path == NULL)
		return got_error_from_errno();
		
	new->data = data;

	RB_INSERT(got_pathset_tree, &set->entries, new);
	set->totelem++;
	return NULL;
}

static struct got_pathset_element *
find_element(struct got_pathset *set, const char *path)
{
	struct got_pathset_element key, *entry;
	key.path = (char *)path;
	key.data = NULL;
	entry = RB_FIND(got_pathset_tree, &set->entries, &key);
	return entry;
}

void *
got_pathset_get(struct got_pathset *set, const char *path)
{
	struct got_pathset_element *entry = find_element(set, path);
	return entry ? entry->data : NULL;
}

const struct got_error *
got_pathset_remove(void **data, struct got_pathset *set, const char *path)
{
	struct got_pathset_element *entry;

	if (data)
		*data = NULL;

	if (set->totelem == 0)
		return got_error(GOT_ERR_NO_OBJ);

	if (path == NULL)
		entry = RB_ROOT(&set->entries);
	else
		entry = find_element(set, path);
	if (entry == NULL)
		return got_error(GOT_ERR_NO_OBJ);

	RB_REMOVE(got_pathset_tree, &set->entries, entry);
	if (data)
		*data = entry->data;
	free_element(entry);
	set->totelem--;
	return NULL;
}

int
got_pathset_contains(struct got_pathset *set, const char *path)
{
	struct got_pathset_element *entry = find_element(set, path);
	return entry ? 1 : 0;
}

const struct got_error *
got_pathset_for_each_safe(struct got_pathset *set,
    const struct got_error *(*cb)(const char *, void *, void *), void *arg)
{
	const struct got_error *err;
	struct got_pathset_element *entry, *tmp;

	RB_FOREACH_SAFE(entry, got_pathset_tree, &set->entries, tmp) {
		err = (*cb)(entry->path, entry->data, arg);
		if (err)
			return err;
	}
	return NULL;
}

const struct got_error *
got_pathset_for_each_reverse_safe(struct got_pathset *set,
    const struct got_error *(*cb)(const char *, void *, void *), void *arg)
{
	const struct got_error *err;
	struct got_pathset_element *entry, *tmp;

	RB_FOREACH_REVERSE_SAFE(entry, got_pathset_tree, &set->entries, tmp) {
		err = (*cb)(entry->path, entry->data, arg);
		if (err)
			return err;
	}
	return NULL;
}

int
got_pathset_num_elements(struct got_pathset *set)
{
	return set->totelem;
}

RB_GENERATE(got_pathset_tree, got_pathset_element, entry, cmp_elements);
