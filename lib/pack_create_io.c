/*
 * Copyright (c) 2020 Ori Bernstein
 * Copyright (c) 2021, 2022 Stefan Sperling <stsp@openbsd.org>
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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/uio.h>

#include <sha1.h>
#include <sha2.h>
#include <limits.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <imsg.h>
#include <inttypes.h>
#include <unistd.h>

#include "got_error.h"
#include "got_cancel.h"
#include "got_object.h"
#include "got_reference.h"
#include "got_repository_admin.h"
#include "got_path.h"

#include "got_lib_delta.h"
#include "got_lib_hash.h"
#include "got_lib_object.h"
#include "got_lib_object_cache.h"
#include "got_lib_object_idset.h"
#include "got_lib_ratelimit.h"
#include "got_lib_pack.h"
#include "got_lib_pack_create.h"
#include "got_lib_repository.h"

static const struct got_error *
get_base_object_id(struct got_object_id *base_id, struct got_packidx *packidx,
    off_t base_offset)
{
	const struct got_error *err;
	int idx;

	err = got_packidx_get_offset_idx(&idx, packidx, base_offset);
	if (err)
		return err;
	if (idx == -1)
		return got_error(GOT_ERR_BAD_PACKIDX);

	return got_packidx_get_object_id(base_id, packidx, idx);
}

struct search_deltas_arg {
	struct got_pack_metavec *v;
	struct got_packidx *packidx;
	struct got_pack *pack;
	struct got_object_idset *idset;
	int ncolored, nfound, ntrees, ncommits;
	got_pack_progress_cb progress_cb;
	void *progress_arg;
	struct got_ratelimit *rl;
	got_cancel_cb cancel_cb;
	void *cancel_arg;
};

static const struct got_error *
search_delta_for_object(struct got_object_id *id, void *data, void *arg)
{
	const struct got_error *err;
	struct search_deltas_arg *a = arg;
	int obj_idx;
	uint8_t *delta_buf = NULL;
	uint64_t base_size, result_size;
	size_t delta_size, delta_compressed_size;
	off_t delta_offset, delta_data_offset, base_offset;
	struct got_object_id base_id;

	if (a->cancel_cb) {
		err = a->cancel_cb(a->cancel_arg);
		if (err)
			return err;
	}

	obj_idx = got_packidx_get_object_idx(a->packidx, id);
	if (obj_idx == -1)
		return NULL; /* object not present in our pack file */

	err = got_packfile_extract_raw_delta(&delta_buf, &delta_size,
	    &delta_compressed_size, &delta_offset, &delta_data_offset,
	    &base_offset, &base_id, &base_size, &result_size,
	    a->pack, a->packidx, obj_idx);
	if (err) {
		if (err->code == GOT_ERR_OBJ_TYPE)
			return NULL; /* object not stored as a delta */
		return err;
	}

	/*
	 * If this is an offset delta we must determine the base
	 * object ID ourselves.
	 */
	if (base_offset != 0) {
		err = get_base_object_id(&base_id, a->packidx, base_offset);
		if (err)
			goto done;
	}

	if (got_object_idset_contains(a->idset, &base_id)) {
		struct got_pack_meta *m, *base;

		m = got_object_idset_get(a->idset, id);
		if (m == NULL) {
			err = got_error_msg(GOT_ERR_NO_OBJ,
			    "delta object not found");
			goto done;
		}

		base = got_object_idset_get(a->idset, &base_id);
		if (m == NULL) {
			err = got_error_msg(GOT_ERR_NO_OBJ,
			    "delta base object not found");
			goto done;
		}

		m->base_obj_id = got_object_id_dup(&base_id);
		if (m->base_obj_id == NULL) {
			err = got_error_from_errno("got_object_id_dup");
			goto done;
		}

		m->prev = base;
		m->size = result_size;
		m->delta_len = delta_size;
		m->delta_compressed_len = delta_compressed_size;
		m->reused_delta_offset = delta_data_offset;
		m->delta_offset = 0;

		err = got_pack_add_meta(m, a->v);
		if (err)
			goto done;

		err = got_pack_report_progress(a->progress_cb, a->progress_arg,
		    a->rl, a->ncolored, a->nfound, a->ntrees, 0L, a->ncommits,
		    got_object_idset_num_elements(a->idset), a->v->nmeta, 0, 0);
		if (err)
			goto done;
	}
done:
	free(delta_buf);
	return err;
}

const struct got_error *
got_pack_search_deltas(struct got_packidx **packidx, struct got_pack **pack,
    struct got_pack_metavec *v, struct got_object_idset *idset,
    int ncolored, int nfound, int ntrees, int ncommits,
    struct got_repository *repo,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct search_deltas_arg sda;

	*packidx = NULL;
	*pack = NULL;

	err = got_pack_find_pack_for_reuse(packidx, repo);
	if (err)
		return err;

	if (*packidx == NULL)
		return NULL;

	err = got_pack_cache_pack_for_packidx(pack, *packidx, repo);
	if (err)
		return err;

	memset(&sda, 0, sizeof(sda));
	sda.v = v;
	sda.idset = idset;
	sda.pack = *pack;
	sda.packidx = *packidx;
	sda.ncolored = ncolored;
	sda.nfound = nfound;
	sda.ntrees = ntrees;
	sda.ncommits = ncommits;
	sda.progress_cb = progress_cb;
	sda.progress_arg = progress_arg;
	sda.rl = rl;
	sda.cancel_cb = cancel_cb;
	sda.cancel_arg = cancel_arg;
	return got_object_idset_for_each(idset, search_delta_for_object, &sda);
}

const struct got_error *
got_pack_load_packed_object_ids(int *found_all_objects,
    struct got_object_id **ours, int nours,
    struct got_object_id **theirs, int ntheirs,
    int want_meta, uint32_t seed, struct got_object_idset *idset,
    struct got_object_idset *idset_exclude, int loose_obj_only,
    struct got_repository *repo, struct got_packidx *packidx,
    int *ncolored, int *nfound, int *ntrees,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg)
{
	/* We do not need this optimized traversal while using direct I/O. */
	*found_all_objects = 0;
	return NULL;
}

const struct got_error *
got_pack_paint_commits(int *ncolored, struct got_object_id_queue *ids, int nids,
    struct got_object_idset *keep, struct got_object_idset *drop,
    struct got_object_idset *skip, struct got_repository *repo,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_commit_object *commit = NULL;
	struct got_packidx *packidx = NULL;
	struct got_pack *pack = NULL;
	const struct got_object_id_queue *parents;
	struct got_object_qid *qid = NULL;
	int nqueued = nids, nskip = 0;

	while (!STAILQ_EMPTY(ids) && nskip != nqueued) {
		intptr_t color;

		if (cancel_cb) {
			err = cancel_cb(cancel_arg);
			if (err)
				break;
		}

		qid = STAILQ_FIRST(ids);
		STAILQ_REMOVE_HEAD(ids, entry);
		nqueued--;
		color = (intptr_t)qid->data;
		if (color == COLOR_SKIP)
			nskip--;

		if (got_object_idset_contains(skip, &qid->id)) {
			got_object_qid_free(qid);
			qid = NULL;
			continue;
		}
		if (color == COLOR_KEEP &&
		    got_object_idset_contains(keep, &qid->id)) {
			got_object_qid_free(qid);
			qid = NULL;
			continue;
		}
		if (color == COLOR_DROP &&
		    got_object_idset_contains(drop, &qid->id)) {
			got_object_qid_free(qid);
			qid = NULL;
			continue;
		}

		switch (color) {
		case COLOR_KEEP:
			if (got_object_idset_contains(drop, &qid->id)) {
				err = got_pack_paint_commit(qid, COLOR_SKIP);
				if (err)
					goto done;
				err = got_object_idset_add(skip, &qid->id,
				    NULL);
				if (err)
					goto done;
			} else
				(*ncolored)++;
			err = got_object_idset_add(keep, &qid->id, NULL);
			if (err)
				goto done;
			break;
		case COLOR_DROP:
			if (got_object_idset_contains(keep, &qid->id)) {
				err = got_pack_paint_commit(qid, COLOR_SKIP);
				if (err)
					goto done;
				err = got_object_idset_add(skip, &qid->id,
				    NULL);
				if (err)
					goto done;
			} else
				(*ncolored)++;
			err = got_object_idset_add(drop, &qid->id, NULL);
			if (err)
				goto done;
			break;
		case COLOR_SKIP:
			if (!got_object_idset_contains(skip, &qid->id)) {
				err = got_object_idset_add(skip, &qid->id,
				    NULL);
				if (err)
					goto done;
			}
			break;
		default:
			/* should not happen */
			err = got_error_fmt(GOT_ERR_NOT_IMPL,
			    "%s invalid commit color %"PRIdPTR, __func__,
			    color);
			goto done;
		}

		err = got_pack_report_progress(progress_cb, progress_arg, rl,
		    *ncolored, 0, 0, 0L, 0, 0, 0, 0, 0);
		if (err)
			break;

		err = got_object_open_as_commit(&commit, repo, &qid->id);
		if (err)
			break;

		parents = got_object_commit_get_parent_ids(commit);
		if (parents) {
			struct got_object_qid *pid;
			color = (intptr_t)qid->data;
			STAILQ_FOREACH(pid, parents, entry) {
				err = got_pack_queue_commit_id(ids, &pid->id,
				    color, repo);
				if (err)
					goto done;
				nqueued++;
				if (color == COLOR_SKIP)
					nskip++;
			}
		}

		if (pack == NULL && (commit->flags & GOT_COMMIT_FLAG_PACKED)) {
			/*
			 * We now know that at least one pack file exists.
			 * Pin a suitable pack to ensure it remains cached
			 * while we are churning through commit history.
			 */
			if (packidx == NULL) {
				err = got_pack_find_pack_for_commit_painting(
				    &packidx, ids, repo);
				if (err)
					goto done;
			}
			if (packidx != NULL) {
				err = got_pack_cache_pack_for_packidx(&pack,
				    packidx, repo);
				if (err)
					goto done;
				err = got_repo_pin_pack(repo, packidx, pack);
				if (err)
					goto done;
			}
		}

		got_object_commit_close(commit);
		commit = NULL;

		got_object_qid_free(qid);
		qid = NULL;
	}
done:
	if (commit)
		got_object_commit_close(commit);
	got_object_qid_free(qid);
	got_repo_unpin_pack(repo);
	return err;
}
