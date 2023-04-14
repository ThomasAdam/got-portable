/*
 * Copyright (c) 2022 Stefan Sperling <stsp@openbsd.org>
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
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <zlib.h>
#include <limits.h>
#include <time.h>
#include <errno.h>

#include "got_compat.h"

#include "got_object.h"
#include "got_error.h"

#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_object_qid.h"
#include "got_lib_object_idset.h"
#include "got_lib_object_parse.h"

#define GOT_OBJECT_IDSET_MIN_BUCKETS	64

struct got_object_idset {
	struct got_object_id_queue *ids;
	size_t nbuckets;
	unsigned int totelem;
	unsigned int flags;
#define GOT_OBJECT_IDSET_F_TRAVERSAL	0x01
#define GOT_OBJECT_IDSET_F_NOMEM	0x02
	SIPHASH_KEY key;
};

struct got_object_idset *
got_object_idset_alloc(void)
{
	struct got_object_idset *set;
	int i;

	set = malloc(sizeof(*set));
	if (set == NULL)
		return NULL;

	set->ids = calloc(sizeof(set->ids[0]), GOT_OBJECT_IDSET_MIN_BUCKETS);
	if (set->ids == NULL) {
		free(set);
		return NULL;
	}
	for (i = 0; i < GOT_OBJECT_IDSET_MIN_BUCKETS; i++)
		STAILQ_INIT(&set->ids[i]);

	set->totelem = 0;
	set->nbuckets = GOT_OBJECT_IDSET_MIN_BUCKETS;
	set->flags = 0;
	arc4random_buf(&set->key, sizeof(set->key));
	return set;
}

void
got_object_idset_free(struct got_object_idset *set)
{
	size_t i;
	struct got_object_qid *qid;

	for (i = 0; i < set->nbuckets; i++) {
		while (!STAILQ_EMPTY(&set->ids[i])) {
			qid = STAILQ_FIRST(&set->ids[i]);
			STAILQ_REMOVE(&set->ids[i], qid, got_object_qid, entry);
			got_object_qid_free(qid);
		}
	}
	/* User data should be freed by caller. */
	free(set->ids);
	free(set);
}

static uint64_t
idset_hash(struct got_object_idset *set, struct got_object_id *id)
{
	return SipHash24(&set->key, id->sha1, sizeof(id->sha1));
}

static const struct got_error *
idset_resize(struct got_object_idset *set, size_t nbuckets)
{
	struct got_object_id_queue *ids;
	size_t i;

	ids = calloc(nbuckets, sizeof(ids[0]));
	if (ids == NULL) {
		if (errno != ENOMEM)
			return got_error_from_errno("calloc");
		/* Proceed with our current amount of hash buckets. */
		set->flags |= GOT_OBJECT_IDSET_F_NOMEM;
		return NULL;
	}

	for (i = 0; i < nbuckets; i++)
		STAILQ_INIT(&ids[i]);

	arc4random_buf(&set->key, sizeof(set->key));

	for (i = 0; i < set->nbuckets; i++) {
		while (!STAILQ_EMPTY(&set->ids[i])) {
			struct got_object_qid *qid;
			uint64_t idx;
			qid = STAILQ_FIRST(&set->ids[i]);
			STAILQ_REMOVE(&set->ids[i], qid, got_object_qid, entry);
			idx = idset_hash(set, &qid->id) % nbuckets;
			STAILQ_INSERT_HEAD(&ids[idx], qid, entry);
		}
	}

	free(set->ids);
	set->ids = ids;
	set->nbuckets = nbuckets;
	return NULL;
}

static const struct got_error *
idset_grow(struct got_object_idset *set)
{
	size_t nbuckets;

	if (set->flags & GOT_OBJECT_IDSET_F_NOMEM)
		return NULL;

	if (set->nbuckets >= UINT_MAX / 2)
		nbuckets = UINT_MAX;
	else
		nbuckets = set->nbuckets * 2;

	return idset_resize(set, nbuckets);
}

const struct got_error *
got_object_idset_add(struct got_object_idset *set, struct got_object_id *id,
    void *data)
{
	const struct got_error *err;
	struct got_object_qid *qid;
	uint64_t idx;
	struct got_object_id_queue *head;

	/* This function may resize the set. */
	if (set->flags & GOT_OBJECT_IDSET_F_TRAVERSAL)
		return got_error_msg(GOT_ERR_NOT_IMPL,
		    "cannot add elements to idset during traversal");

	if (set->totelem == UINT_MAX)
		return got_error(GOT_ERR_NO_SPACE);

	err = got_object_qid_alloc_partial(&qid);
	if (err)
		return err;
	memcpy(&qid->id, id, sizeof(qid->id));
	qid->data = data;

	idx = idset_hash(set, id) % set->nbuckets;
	head = &set->ids[idx];
	STAILQ_INSERT_HEAD(head, qid, entry);
	set->totelem++;

	if (set->nbuckets < set->totelem)
		err = idset_grow(set);

	return err;
}

static struct got_object_qid *
find_element(struct got_object_idset *set, struct got_object_id *id)
{
	uint64_t idx = idset_hash(set, id) % set->nbuckets;
	struct got_object_id_queue *head = &set->ids[idx];
	struct got_object_qid *qid;

	STAILQ_FOREACH(qid, head, entry) {
		if (got_object_id_cmp(&qid->id, id) == 0)
			return qid;
	}

	return NULL;
}

void *
got_object_idset_get(struct got_object_idset *set, struct got_object_id *id)
{
	struct got_object_qid *qid = find_element(set, id);
	return qid ? qid->data : NULL;
}

const struct got_error *
got_object_idset_remove(void **data, struct got_object_idset *set,
    struct got_object_id *id)
{
	uint64_t idx;
	struct got_object_id_queue *head;
	struct got_object_qid *qid;

	if (data)
		*data = NULL;

	if (set->totelem == 0)
		return got_error(GOT_ERR_NO_OBJ);

	if (id == NULL) {
		/* Remove a "random" element. */
		for (idx = 0; idx < set->nbuckets; idx++) {
			head = &set->ids[idx];
			qid = STAILQ_FIRST(head);
			if (qid)
				break;
		}
	} else {
		idx = idset_hash(set, id) % set->nbuckets;
		head = &set->ids[idx];
		STAILQ_FOREACH(qid, head, entry) {
			if (got_object_id_cmp(&qid->id, id) == 0)
				break;
		}
		if (qid == NULL)
			return got_error_no_obj(id);
	}

	if (data)
		*data = qid->data;
	STAILQ_REMOVE(head, qid, got_object_qid, entry);
	got_object_qid_free(qid);
	set->totelem--;

	return NULL;
}

int
got_object_idset_contains(struct got_object_idset *set,
    struct got_object_id *id)
{
	struct got_object_qid *qid = find_element(set, id);
	return qid ? 1 : 0;
}

const struct got_error *
got_object_idset_for_each(struct got_object_idset *set,
    const struct got_error *(*cb)(struct got_object_id *, void *, void *),
    void *arg)
{
	const struct got_error *err = NULL;
	struct got_object_id_queue *head;
	struct got_object_qid *qid, *tmp;
	size_t i;

	set->flags |= GOT_OBJECT_IDSET_F_TRAVERSAL;
	for (i = 0; i < set->nbuckets; i++) {
		head = &set->ids[i];
		STAILQ_FOREACH_SAFE(qid, head, entry, tmp) {
			err = (*cb)(&qid->id, qid->data, arg);
			if (err)
				goto done;
		}
	}
done:
	set->flags &= ~GOT_OBJECT_IDSET_F_TRAVERSAL;
	return err;
}

int
got_object_idset_num_elements(struct got_object_idset *set)
{
	return set->totelem;
}
