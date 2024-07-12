/*
 * Copyright (c) 2018, 2019, 2020, 2023 Stefan Sperling <stsp@openbsd.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sha1.h>
#include <sha2.h>

#include "got_object.h"
#include "got_error.h"

#include "got_lib_object_qid.h"
#include "got_lib_hash.h"

const struct got_error *
got_object_qid_alloc_partial(struct got_object_qid **qid)
{
	/*
	 * XXX(op) this should really be malloc(), but there are
	 * strange interactions in the fileindex and worktree code
	 * that are creating issues with some of the changes needed
	 * for sha256 support.  This will have to be revisited once
	 * that code is fixed.
	 */
	*qid = calloc(1, sizeof(**qid));
	if (*qid == NULL)
		return got_error_from_errno("calloc");

	(*qid)->data = NULL;
	return NULL;
}

const struct got_error *
got_object_qid_alloc(struct got_object_qid **qid, struct got_object_id *id)
{
	*qid = calloc(1, sizeof(**qid));
	if (*qid == NULL)
		return got_error_from_errno("calloc");

	memcpy(&(*qid)->id, id, sizeof((*qid)->id));
	return NULL;
}

void
got_object_qid_free(struct got_object_qid *qid)
{
	free(qid);
}

void
got_object_id_queue_free(struct got_object_id_queue *ids)
{
	struct got_object_qid *qid;

	while (!STAILQ_EMPTY(ids)) {
		qid = STAILQ_FIRST(ids);
		STAILQ_REMOVE_HEAD(ids, entry);
		got_object_qid_free(qid);
	}
}

const struct got_error *
got_object_id_queue_copy(const struct got_object_id_queue *src,
    struct got_object_id_queue *dest)
{
	const struct got_error *err;
	struct got_object_qid *qid;

	STAILQ_FOREACH(qid, src, entry) {
		struct got_object_qid *new;
		/*
		 * Deep-copy the object ID only. Let the caller deal
		 * with setting up the new->data pointer if needed.
		 */
		err = got_object_qid_alloc(&new, &qid->id);
		if (err) {
			got_object_id_queue_free(dest);
			return err;
		}
		STAILQ_INSERT_TAIL(dest, new, entry);
	}

	return NULL;
}
