/*
 * Copyright (c) 2018, 2019, 2025 Stefan Sperling <stsp@openbsd.org>
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

#include <event.h>
#include <imsg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "got_error.h"

#include "gotsysd.h"

struct gotsys_uidset_element {
	RB_ENTRY(gotsys_uidset_element)	entry;
	uid_t uid;
};

RB_HEAD(gotsys_uidset_tree, gotsys_uidset_element);

static int
cmp_uid(uid_t uid1, uid_t uid2)
{
	if (uid1 > uid2)
		return 1;
	if (uid1 < uid2)
		return -1;
	return 0;
}

static int cmp_elements(const struct gotsys_uidset_element *e1,
    const struct gotsys_uidset_element *e2)
{
	return cmp_uid(e1->uid, e2->uid);
}

RB_PROTOTYPE(gotsys_uidset_tree, gotsys_uidset_element, entry,
    cmp_elements);

struct gotsys_uidset {
	struct gotsys_uidset_tree entries;
	int totelem;
#define GOTSYS_UIDSET_MAX_ELEM INT_MAX
};

struct gotsys_uidset *
gotsys_uidset_alloc(void)
{
	struct gotsys_uidset *set;

	set = malloc(sizeof(*set));
	if (set == NULL)
		return NULL;

	RB_INIT(&set->entries);
	set->totelem = 0;

	return set;
}

void
gotsys_uidset_free(struct gotsys_uidset *set)
{
	struct gotsys_uidset_element *entry;

	if (set == NULL)
		return;

	while ((entry = RB_MIN(gotsys_uidset_tree, &set->entries))) {
		RB_REMOVE(gotsys_uidset_tree, &set->entries, entry);
		free(entry);
	}

	free(set);
}

const struct got_error *
gotsys_uidset_add(struct gotsys_uidset *set, uid_t uid)
{
	struct gotsys_uidset_element *new;

	if (set->totelem >= GOTSYS_UIDSET_MAX_ELEM)
		return got_error(GOT_ERR_NO_SPACE);

	new = malloc(sizeof(*new));
	if (new == NULL)
		return got_error_from_errno("malloc");

	new->uid = uid;

	if (RB_INSERT(gotsys_uidset_tree, &set->entries, new) != NULL) {
		free(new);
		return got_error(GOT_ERR_USER_EXISTS);
	}

	set->totelem++;
	return NULL;
}

static struct gotsys_uidset_element *
find_element(struct gotsys_uidset *set, uid_t uid)
{
	struct gotsys_uidset_element *entry;

	entry = RB_ROOT(&set->entries);
	while (entry) {
		int cmp = cmp_uid(uid, entry->uid);
		if (cmp < 0)
			entry = RB_LEFT(entry, entry);
		else if (cmp > 0)
			entry = RB_RIGHT(entry, entry);
		else
			break;
	}

	return entry;
}

const struct got_error *
gotsys_uidset_remove(void **data, struct gotsys_uidset *set, uid_t uid)
{
	struct gotsys_uidset_element *entry;

	if (set->totelem == 0)
		return got_error(GOT_ERR_UID);

	entry = find_element(set, uid);
	if (entry == NULL)
		return got_error(GOT_ERR_UID);

	RB_REMOVE(gotsys_uidset_tree, &set->entries, entry);
	free(entry);
	set->totelem--;
	return NULL;
}

int
gotsys_uidset_contains(struct gotsys_uidset *set, uid_t uid)
{
	struct gotsys_uidset_element *entry = find_element(set, uid);
	return entry ? 1 : 0;
}

uid_t
gotsys_uidset_min_uid(struct gotsys_uidset *set, uid_t fallback)
{
	struct gotsys_uidset_element *entry;

	if (RB_EMPTY(&set->entries))
		return fallback;

	entry = RB_MIN(gotsys_uidset_tree, &set->entries);
	return entry->uid;
}

uid_t
gotsys_uidset_max_uid(struct gotsys_uidset *set, uid_t fallback)
{
	struct gotsys_uidset_element *entry;

	if (RB_EMPTY(&set->entries))
		return fallback;

	entry = RB_MAX(gotsys_uidset_tree, &set->entries);
	return entry->uid;
}

const struct got_error *
gotsys_uidset_for_each(struct gotsys_uidset *set,
    const struct got_error *(*cb)(uid_t, void *),
    void *arg)
{
	const struct got_error *err;
	struct gotsys_uidset_element *entry, *tmp;

	RB_FOREACH_SAFE(entry, gotsys_uidset_tree, &set->entries, tmp) {
		err = (*cb)(entry->uid, arg);
		if (err)
			return err;
	}
	return NULL;
}

int
gotsys_uidset_num_elements(struct gotsys_uidset *set)
{
	return set->totelem;
}

struct gotsys_uidset_element *
gotsys_uidset_get_element(struct gotsys_uidset *set, uid_t uid)
{
	return find_element(set, uid);
}

const struct got_error *
gotsys_uidset_for_each_element(struct gotsys_uidset *set,
    const struct got_error *(*cb)(struct gotsys_uidset_element *, void *),
    void *arg)
{
	const struct got_error *err;
	struct gotsys_uidset_element *entry, *tmp;

	RB_FOREACH_SAFE(entry, gotsys_uidset_tree, &set->entries, tmp) {
		err = (*cb)(entry, arg);
		if (err)
			return err;
	}
	return NULL;
}

void
gotsys_uidset_remove_element(struct gotsys_uidset *set,
    struct gotsys_uidset_element *entry)
{
	RB_REMOVE(gotsys_uidset_tree, &set->entries, entry);
	free(entry);
	set->totelem--;
}

RB_GENERATE(gotsys_uidset_tree, gotsys_uidset_element, entry,
    cmp_elements);
