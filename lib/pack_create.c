/*
 * Copyright (c) 2020 Ori Bernstein
 * Copyright (c) 2021 Stefan Sperling <stsp@openbsd.org>
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
#include <sys/stat.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <zlib.h>

#include "got_error.h"
#include "got_cancel.h"
#include "got_object.h"
#include "got_path.h"
#include "got_reference.h"
#include "got_repository_admin.h"
#include "got_opentemp.h"

#include "got_lib_deltify.h"
#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_object_idset.h"
#include "got_lib_object_cache.h"
#include "got_lib_deflate.h"
#include "got_lib_pack.h"
#include "got_lib_privsep.h"
#include "got_lib_repository.h"

#ifndef MAX
#define	MAX(_a,_b) ((_a) > (_b) ? (_a) : (_b))
#endif

struct got_pack_meta {
	struct got_object_id id;
	char	*path;
	int	obj_type;
	off_t	size;
	time_t	mtime;

	/* The best delta we picked */
	struct got_pack_meta *head;
	struct got_pack_meta *prev;
	struct got_delta_instruction *deltas;
	int	ndeltas;
	int	nchain;

	/* Only used for delta window */
	struct got_delta_table *dtab;

	/* Only used for writing offset deltas */
	off_t	off;
};

struct got_pack_metavec {
	struct got_pack_meta **meta;
	int nmeta;
	int metasz;
};

static const struct got_error *
alloc_meta(struct got_pack_meta **new, struct got_object_id *id,
    const char *path, int obj_type, time_t mtime)
{
	const struct got_error *err = NULL;
	struct got_pack_meta *m;

	*new = NULL;

	m = calloc(1, sizeof(*m));
	if (m == NULL)
		return got_error_from_errno("calloc");

	memcpy(&m->id, id, sizeof(m->id));

	m->path = strdup(path);
	if (m->path == NULL) {
		err = got_error_from_errno("strdup");
		free(m);
		return err;
	}

	m->obj_type = obj_type;
	m->mtime = mtime;
	*new = m;
	return NULL;
}

static void
clear_meta(struct got_pack_meta *meta)
{
	if (meta == NULL)
		return;
	free(meta->deltas);
	meta->deltas = NULL;
	free(meta->path);
	meta->path = NULL;
}

static void
free_nmeta(struct got_pack_meta **meta, int nmeta)
{
	int i;

	for (i = 0; i < nmeta; i++)
		clear_meta(meta[i]);
	free(meta);
}

static int
delta_order_cmp(const void *pa, const void *pb)
{
	struct got_pack_meta *a, *b;
	int cmp;

	a = *(struct got_pack_meta **)pa;
	b = *(struct got_pack_meta **)pb;

	if (a->obj_type != b->obj_type)
		return a->obj_type - b->obj_type;
	cmp = strcmp(a->path, b->path);
	if (cmp != 0)
		return cmp;
	if (a->mtime != b->mtime)
		return a->mtime - b->mtime;
	return got_object_id_cmp(&a->id, &b->id);
}

static int
delta_size(struct got_delta_instruction *deltas, int ndeltas)
{
	int i, size = 32;
	for (i = 0; i < ndeltas; i++) {
		if (deltas[i].copy)
			size += GOT_DELTA_SIZE_SHIFT;
		else
			size += deltas[i].len + 1;
	}
	return size;
}


static const struct got_error *
pick_deltas(struct got_pack_meta **meta, int nmeta, int nours,
    struct got_repository *repo,
    got_pack_progress_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_pack_meta *m = NULL, *base = NULL;
	struct got_raw_object *raw = NULL, *base_raw = NULL;
	struct got_delta_instruction *deltas;
	int i, j, size, ndeltas, best;
	const int max_base_candidates = 10;
	int outfd = -1;

	qsort(meta, nmeta, sizeof(struct got_pack_meta *), delta_order_cmp);
	for (i = 0; i < nmeta; i++) {
		if (cancel_cb) {
			err = (*cancel_cb)(cancel_arg);
			if (err)
				break;
		}
		if (progress_cb) {
			err = progress_cb(progress_arg, 0L, nours, nmeta, i, 0);
			if (err)
				goto done;
		}
		m = meta[i];
		m->deltas = NULL;
		m->ndeltas = 0;

		if (m->obj_type == GOT_OBJ_TYPE_COMMIT ||
		    m->obj_type == GOT_OBJ_TYPE_TAG)
			continue;

		err = got_object_raw_open(&raw, &outfd, repo, &m->id, 8192);
		if (err)
			goto done;
		m->size = raw->size;

		err = got_deltify_init(&m->dtab, raw->f, raw->hdrlen,
		    raw->size + raw->hdrlen);
		if (err)
			goto done;

		if (i > max_base_candidates) {
			struct got_pack_meta *n = NULL;
			n = meta[i - (max_base_candidates + 1)];
			got_deltify_free(n->dtab);
			n->dtab = NULL;
		}

		best = raw->size;
		for (j = MAX(0, i - max_base_candidates); j < i; j++) {
			if (cancel_cb) {
				err = (*cancel_cb)(cancel_arg);
				if (err)
					goto done;
			}
			base = meta[j];
			/* long chains make unpacking slow, avoid such bases */
			if (base->nchain >= 128 ||
			    base->obj_type != m->obj_type)
				continue;

			err = got_object_raw_open(&base_raw, &outfd, repo,
			    &base->id, 8192);
			if (err)
				goto done;
			err = got_deltify(&deltas, &ndeltas,
			    raw->f, raw->hdrlen, raw->size + raw->hdrlen,
			    base->dtab, base_raw->f, base_raw->hdrlen,
			    base_raw->size + base_raw->hdrlen);
			got_object_raw_close(base_raw);
			base_raw = NULL;
			if (err)
				goto done;

			size = delta_size(deltas, ndeltas);
			if (size + 32 < best){
				/*
				 * if we already picked a best delta,
				 * replace it.
				 */
				free(m->deltas);
				best = size;
				m->deltas = deltas;
				m->ndeltas = ndeltas;
				m->nchain = base->nchain + 1;
				m->prev = base;
				m->head = base->head;
				if (m->head == NULL)
					m->head = base;
			} else {
				free(deltas);
				deltas = NULL;
				ndeltas = 0;
			}
		}

		got_object_raw_close(raw);
		raw = NULL;
	}
done:
	for (i = MAX(0, nmeta - max_base_candidates); i < nmeta; i++) {
		got_deltify_free(meta[i]->dtab);
		meta[i]->dtab = NULL;
	}
	if (raw)
		got_object_raw_close(raw);
	if (base_raw)
		got_object_raw_close(base_raw);
	if (outfd != -1 && close(outfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	return err;
}

static const struct got_error *
search_packidx(int *found, struct got_object_id *id,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_packidx *packidx = NULL;
	int idx;

	*found = 0;

	err = got_repo_search_packidx(&packidx, &idx, repo, id);
	if (err == NULL)
		*found = 1; /* object is already packed */
	else if (err->code == GOT_ERR_NO_OBJ)
		err = NULL;
	return err;
}

static const int obj_types[] = {
	GOT_OBJ_TYPE_ANY,
	GOT_OBJ_TYPE_COMMIT,
	GOT_OBJ_TYPE_TREE,
	GOT_OBJ_TYPE_BLOB,
	GOT_OBJ_TYPE_TAG,
	GOT_OBJ_TYPE_OFFSET_DELTA,
	GOT_OBJ_TYPE_REF_DELTA
};

static const struct got_error *
add_meta(struct got_pack_metavec *v, struct got_object_idset *idset,
    struct got_object_id *id, const char *path, int obj_type,
    time_t mtime, int loose_obj_only, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_pack_meta *m;

	if (loose_obj_only) {
		int is_packed;
		err = search_packidx(&is_packed, id, repo);
		if (err)
			return err;
		if (is_packed)
			return NULL;
	}

	err = got_object_idset_add(idset, id, (void *)&obj_types[obj_type]);
	if (err)
		return err;

	if (v == NULL)
		return NULL;

	err = alloc_meta(&m, id, path, obj_type, mtime);
	if (err)
		goto done;

	if (v->nmeta == v->metasz){
		size_t newsize = 2 * v->metasz;
		struct got_pack_meta **new;
		new = reallocarray(v->meta, newsize, sizeof(*new));
		if (new == NULL) {
			err = got_error_from_errno("reallocarray");
			goto done;
		}
		v->meta = new;
		v->metasz = newsize; 
	}
done:
	if (err) {
		clear_meta(m);
		free(m);
	} else
		v->meta[v->nmeta++] = m;

	return err;
}

static const struct got_error *
load_tree_entries(struct got_object_id_queue *ids, struct got_pack_metavec *v,
    struct got_object_idset *idset, struct got_object_id *tree_id,
    const char *dpath, time_t mtime, struct got_repository *repo,
    int loose_obj_only, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err;
	struct got_tree_object *tree;
	char *p = NULL;
	int i;

	err = got_object_open_as_tree(&tree, repo, tree_id);
	if (err)
		return err;

	for (i = 0; i < got_object_tree_get_nentries(tree); i++) {
		struct got_tree_entry *e = got_object_tree_get_entry(tree, i);
		struct got_object_id *id = got_tree_entry_get_id(e);
		mode_t mode = got_tree_entry_get_mode(e);

		if (cancel_cb) {
			err = (*cancel_cb)(cancel_arg);
			if (err)
				break;
		}

		if (got_object_tree_entry_is_submodule(e) ||
		    got_object_idset_contains(idset, id))
			continue;
		
		if (asprintf(&p, "%s%s%s", dpath, dpath[0] != '\0' ? "/" : "",
		    got_tree_entry_get_name(e)) == -1) {
			err = got_error_from_errno("asprintf");
			break;
		}

		if (S_ISDIR(mode)) {
			struct got_object_qid *qid;
			err = got_object_qid_alloc(&qid, id);
			if (err)
				break;
			STAILQ_INSERT_TAIL(ids, qid, entry);
		} else if (S_ISREG(mode) || S_ISLNK(mode)) {
			err = add_meta(v, idset, id, p, GOT_OBJ_TYPE_BLOB,
			    mtime, loose_obj_only, repo);
			if (err)
				break;
		}
		free(p);
		p = NULL;
	}

	got_object_tree_close(tree);
	free(p);
	return err;
}

static const struct got_error *
load_tree(struct got_pack_metavec *v, struct got_object_idset *idset,
    struct got_object_id *tree_id, const char *dpath, time_t mtime,
    int loose_obj_only, struct got_repository *repo,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_object_id_queue tree_ids;
	struct got_object_qid *qid;

	if (got_object_idset_contains(idset, tree_id))
		return NULL;

	err = got_object_qid_alloc(&qid, tree_id);
	if (err)
		return err;

	STAILQ_INIT(&tree_ids);
	STAILQ_INSERT_TAIL(&tree_ids, qid, entry);

	while (!STAILQ_EMPTY(&tree_ids)) {
		if (cancel_cb) {
			err = (*cancel_cb)(cancel_arg);
			if (err)
				break;
		}

		qid = STAILQ_FIRST(&tree_ids);
		STAILQ_REMOVE_HEAD(&tree_ids, entry);

		if (got_object_idset_contains(idset, qid->id)) {
			got_object_qid_free(qid);
			continue;
		}

		err = add_meta(v, idset, qid->id, dpath, GOT_OBJ_TYPE_TREE,
		    mtime, loose_obj_only, repo);
		if (err) {
			got_object_qid_free(qid);
			break;
		}

		err = load_tree_entries(&tree_ids, v, idset, qid->id, dpath,
		    mtime, repo, loose_obj_only, cancel_cb, cancel_arg);
		got_object_qid_free(qid);
		if (err)
			break;
	}

	got_object_id_queue_free(&tree_ids);
	return err;
}

static const struct got_error *
load_commit(struct got_pack_metavec *v, struct got_object_idset *idset,
    struct got_object_id *id, struct got_repository *repo, int loose_obj_only,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err;
	struct got_commit_object *commit;

	if (got_object_idset_contains(idset, id))
		return NULL;

	if (loose_obj_only) {
		int is_packed;
		err = search_packidx(&is_packed, id, repo);
		if (err)
			return err;
		if (is_packed)
			return NULL;
	}

	err = got_object_open_as_commit(&commit, repo, id);
	if (err)
		return err;

	err = add_meta(v, idset, id, "", GOT_OBJ_TYPE_COMMIT,
	    got_object_commit_get_committer_time(commit),
	    loose_obj_only, repo);
	if (err)
		goto done;

	err = load_tree(v, idset, got_object_commit_get_tree_id(commit),
	    "", got_object_commit_get_committer_time(commit),
	    loose_obj_only, repo, cancel_cb, cancel_arg);
done:
	got_object_commit_close(commit);
	return err;
}

static const struct got_error *
load_tag(struct got_pack_metavec *v, struct got_object_idset *idset,
    struct got_object_id *id, struct got_repository *repo, int loose_obj_only,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err;
	struct got_tag_object *tag = NULL;

	if (got_object_idset_contains(idset, id))
		return NULL;

	if (loose_obj_only) {
		int is_packed;
		err = search_packidx(&is_packed, id, repo);
		if (err)
			return err;
		if (is_packed)
			return NULL;
	}

	err = got_object_open_as_tag(&tag, repo, id);
	if (err)
		return err;

	err = add_meta(v, idset, id, "", GOT_OBJ_TYPE_TAG,
	    got_object_tag_get_tagger_time(tag),
	    loose_obj_only, repo);
	if (err)
		goto done;

	switch (got_object_tag_get_object_type(tag)) {
	case GOT_OBJ_TYPE_COMMIT:
		err = load_commit(v, idset,
		    got_object_tag_get_object_id(tag), repo,
		    loose_obj_only, cancel_cb, cancel_arg);
		break;
	case GOT_OBJ_TYPE_TREE:
		err = load_tree(v, idset, got_object_tag_get_object_id(tag),
		    "", got_object_tag_get_tagger_time(tag),
		    loose_obj_only, repo, cancel_cb, cancel_arg);
		break;
	default:
		break;
	}

done:
	got_object_tag_close(tag);
	return err;
}

enum findtwixt_color {
	COLOR_KEEP = 0,
	COLOR_DROP,
	COLOR_BLANK,
};
static const int findtwixt_colors[] = {
	COLOR_KEEP,
	COLOR_DROP,
	COLOR_BLANK
};

static const struct got_error *
queue_commit_id(struct got_object_id_queue *ids, struct got_object_id *id,
    int color, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_object_qid *qid;

	err = got_object_qid_alloc(&qid, id);
	if (err)
		return err;

	STAILQ_INSERT_TAIL(ids, qid, entry);
	qid->data = (void *)&findtwixt_colors[color];
	return NULL;
}

static const struct got_error *
drop_commit(struct got_object_idset *keep, struct got_object_idset *drop,
    struct got_object_id *id, struct got_repository *repo,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_commit_object *commit;
	const struct got_object_id_queue *parents;
	struct got_object_id_queue ids;
	struct got_object_qid *qid;

	STAILQ_INIT(&ids);

	err = got_object_qid_alloc(&qid, id);
	if (err)
		return err;
	STAILQ_INSERT_HEAD(&ids, qid, entry);

	while (!STAILQ_EMPTY(&ids)) {
		if (cancel_cb) {
			err = (*cancel_cb)(cancel_arg);
			if (err)
				break;
		}

		qid = STAILQ_FIRST(&ids);
		STAILQ_REMOVE_HEAD(&ids, entry);

		if (got_object_idset_contains(drop, qid->id)) {
			got_object_qid_free(qid);
			continue;
		}

		err = got_object_idset_add(drop, qid->id,
		    (void *)&obj_types[GOT_OBJ_TYPE_COMMIT]);
		if (err) {
			got_object_qid_free(qid);
			break;
		}

		if (!got_object_idset_contains(keep, qid->id)) {
			got_object_qid_free(qid);
			continue;
		}

		err = got_object_open_as_commit(&commit, repo, qid->id);
		got_object_qid_free(qid);
		if (err)
			break;

		parents = got_object_commit_get_parent_ids(commit);
		if (parents) {
			err = got_object_id_queue_copy(parents, &ids);
			if (err) {
				got_object_commit_close(commit);
				break;
			}
		}
		got_object_commit_close(commit);
	}

	got_object_id_queue_free(&ids);
	return err;
}

struct append_id_arg {
	struct got_object_id **array;
	int idx;
};

static const struct got_error *
append_id(struct got_object_id *id, void *data, void *arg)
{
	struct append_id_arg *a = arg;

	a->array[a->idx] = got_object_id_dup(id);
	if (a->array[a->idx] == NULL)
		return got_error_from_errno("got_object_id_dup");

	a->idx++;
	return NULL;
}

static const struct got_error *
findtwixt(struct got_object_id ***res, int *nres,
    struct got_object_id **head, int nhead,
    struct got_object_id **tail, int ntail,
    struct got_repository *repo,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_object_id_queue ids;
	struct got_object_idset *keep, *drop;
	struct got_object_qid *qid;
	int i, ncolor, nkeep, obj_type;

	STAILQ_INIT(&ids);
	*res = NULL;
	*nres = 0;

	keep = got_object_idset_alloc();
	if (keep == NULL)
		return got_error_from_errno("got_object_idset_alloc");

	drop = got_object_idset_alloc();
	if (drop == NULL) {
		err = got_error_from_errno("got_object_idset_alloc");
		goto done;
	}

	for (i = 0; i < nhead; i++) {
		struct got_object_id *id = head[i];
		if (id == NULL)
			continue;
		err = got_object_get_type(&obj_type, repo, id);
		if (err)
			return err;
		if (obj_type != GOT_OBJ_TYPE_COMMIT)
			continue;
		err = queue_commit_id(&ids, id, COLOR_KEEP, repo);
		if (err)
			goto done;
	}		
	for (i = 0; i < ntail; i++) {
		struct got_object_id *id = tail[i];
		if (id == NULL)
			continue;
		err = got_object_get_type(&obj_type, repo, id);
		if (err)
			return err;
		if (obj_type != GOT_OBJ_TYPE_COMMIT)
			continue;
		err = queue_commit_id(&ids, id, COLOR_DROP, repo);
		if (err)
			goto done;
	}

	while (!STAILQ_EMPTY(&ids)) {
		int qcolor;
		qid = STAILQ_FIRST(&ids);
		qcolor = *((int *)qid->data);

		if (got_object_idset_contains(drop, qid->id))
			ncolor = COLOR_DROP;
		else if (got_object_idset_contains(keep, qid->id))
			ncolor = COLOR_KEEP;
		else
			ncolor = COLOR_BLANK;

		if (ncolor == COLOR_DROP || (ncolor == COLOR_KEEP &&
		    qcolor == COLOR_KEEP)) {
			STAILQ_REMOVE_HEAD(&ids, entry);
			got_object_qid_free(qid);
			continue;
		}

		if (ncolor == COLOR_KEEP && qcolor == COLOR_DROP) {
			err = drop_commit(keep, drop, qid->id, repo,
			    cancel_cb, cancel_arg);
			if (err)
				goto done;
		} else if (ncolor == COLOR_BLANK) {
			struct got_commit_object *commit;
			struct got_object_id *id;
			const struct got_object_id_queue *parents;
			struct got_object_qid *pid;

			id = got_object_id_dup(qid->id);
			if (id == NULL) {
				err = got_error_from_errno("got_object_id_dup");
				goto done;
			}
			if (qcolor == COLOR_KEEP)
				err = got_object_idset_add(keep, id,
				    (void *)&obj_types[GOT_OBJ_TYPE_COMMIT]);
			else
				err = got_object_idset_add(drop, id,
				    (void *)&obj_types[GOT_OBJ_TYPE_COMMIT]);
			if (err) {
				free(id);
				goto done;
			}

			err = got_object_open_as_commit(&commit, repo, id);
			if (err) {
				free(id);
				goto done;
			}
			parents = got_object_commit_get_parent_ids(commit);
			if (parents) {
				STAILQ_FOREACH(pid, parents, entry) {
					err = queue_commit_id(&ids, pid->id,
					    qcolor, repo);
					if (err) {
						free(id);
						goto done;
					}
				}
			}
			got_object_commit_close(commit);
			commit = NULL;
		} else {
			/* should not happen */
			err = got_error_fmt(GOT_ERR_NOT_IMPL,
			    "%s ncolor=%d qcolor=%d", __func__, ncolor, qcolor);
			goto done;
		}

		STAILQ_REMOVE_HEAD(&ids, entry);
		got_object_qid_free(qid);
	}

	nkeep = got_object_idset_num_elements(keep);
	if (nkeep > 0) {
		struct append_id_arg arg;
		arg.array = calloc(nkeep, sizeof(struct got_object_id *));
		if (arg.array == NULL) {
			err = got_error_from_errno("calloc");
			goto done;
		}
		arg.idx = 0;
		err = got_object_idset_for_each(keep, append_id, &arg);
		if (err) {
			free(arg.array);
			goto done;
		}
		*res = arg.array;
		*nres = nkeep;
	}
done:
	got_object_idset_free(keep);
	got_object_idset_free(drop);
	got_object_id_queue_free(&ids);
	return err;
}

static const struct got_error *
read_meta(struct got_pack_meta ***meta, int *nmeta,
    struct got_object_id **theirs, int ntheirs,
    struct got_object_id **ours, int nours, struct got_repository *repo,
    int loose_obj_only, got_pack_progress_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_object_id **ids = NULL;
	struct got_object_idset *idset;
	int i, nobj = 0, obj_type;
	struct got_pack_metavec v;

	*meta = NULL;
	*nmeta = 0;

	idset = got_object_idset_alloc();
	if (idset == NULL)
		return got_error_from_errno("got_object_idset_alloc");

	v.nmeta = 0;
	v.metasz = 64;
	v.meta = calloc(v.metasz, sizeof(struct got_pack_meta *));
	if (v.meta == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}

	err = findtwixt(&ids, &nobj, ours, nours, theirs, ntheirs, repo,
	    cancel_cb, cancel_arg);
	if (err || nobj == 0)
		goto done;

	for (i = 0; i < ntheirs; i++) {
		struct got_object_id *id = theirs[i];
		if (id == NULL)
			continue;
		err = got_object_get_type(&obj_type, repo, id);
		if (err)
			return err;
		if (obj_type != GOT_OBJ_TYPE_COMMIT)
			continue;
		err = load_commit(NULL, idset, id, repo,
		    loose_obj_only, cancel_cb, cancel_arg);
		if (err)
			goto done;
		if (progress_cb) {
			err = progress_cb(progress_arg, 0L, nours,
			    v.nmeta, 0, 0);
			if (err)
				goto done;
		}
	}

	for (i = 0; i < ntheirs; i++) {
		struct got_object_id *id = theirs[i];
		int *cached_type;
		if (id == NULL)
			continue;
		cached_type = got_object_idset_get(idset, id);
		if (cached_type == NULL) {
			err = got_object_get_type(&obj_type, repo, id);
			if (err)
				goto done;
		} else
			obj_type = *cached_type;
		if (obj_type != GOT_OBJ_TYPE_TAG)
			continue;
		err = load_tag(NULL, idset, id, repo,
		    loose_obj_only, cancel_cb, cancel_arg);
		if (err)
			goto done;
		if (progress_cb) {
			err = progress_cb(progress_arg, 0L, nours,
			    v.nmeta, 0, 0);
			if (err)
				goto done;
		}
	}

	for (i = 0; i < nobj; i++) {
		err = load_commit(&v, idset, ids[i], repo,
		    loose_obj_only, cancel_cb, cancel_arg);
		if (err)
			goto done;
		if (progress_cb) {
			err = progress_cb(progress_arg, 0L, nours,
			    v.nmeta, 0, 0);
			if (err)
				goto done;
		}
	}

	for (i = 0; i < nours; i++) {
		struct got_object_id *id = ours[i];
		int *cached_type;
		if (id == NULL)
			continue;
		cached_type = got_object_idset_get(idset, id);
		if (cached_type == NULL) {
			err = got_object_get_type(&obj_type, repo, id);
			if (err)
				goto done;
		} else
			obj_type = *cached_type;
		if (obj_type != GOT_OBJ_TYPE_TAG)
			continue;
		err = load_tag(&v, idset, id, repo,
		    loose_obj_only, cancel_cb, cancel_arg);
		if (err)
			goto done;
		if (progress_cb) {
			err = progress_cb(progress_arg, 0L, nours,
			    v.nmeta, 0, 0);
			if (err)
				goto done;
		}
	}

done:
	for (i = 0; i < nobj; i++) {
		free(ids[i]);
	}
	free(ids);
	got_object_idset_free(idset);
	if (err == NULL) {
		*meta = v.meta;
		*nmeta = v.nmeta;
	} else
		free(v.meta);

	return err;
}

const struct got_error *
hwrite(FILE *f, void *buf, int len, SHA1_CTX *ctx)
{
	size_t n;

	SHA1Update(ctx, buf, len);
	n = fwrite(buf, 1, len, f);
	if (n != len)
		return got_ferror(f, GOT_ERR_IO);
	return NULL;
}

static void
putbe32(char *b, uint32_t n)
{
	b[0] = n >> 24;
	b[1] = n >> 16;
	b[2] = n >> 8;
	b[3] = n >> 0;
}

static int
write_order_cmp(const void *pa, const void *pb)
{
	struct got_pack_meta *a, *b, *ahd, *bhd;

	a = *(struct got_pack_meta **)pa;
	b = *(struct got_pack_meta **)pb;
	ahd = (a->head == NULL) ? a : a->head;
	bhd = (b->head == NULL) ? b : b->head;
	if (ahd->mtime != bhd->mtime)
		return bhd->mtime - ahd->mtime;
	if (ahd != bhd)
		return (uintptr_t)bhd - (uintptr_t)ahd;
	if (a->nchain != b->nchain)
		return a->nchain - b->nchain;
	return a->mtime - b->mtime;
}

static const struct got_error *
packhdr(int *hdrlen, char *hdr, size_t bufsize, int obj_type, size_t len)
{
	size_t i;

	*hdrlen = 0;

	hdr[0] = obj_type << 4;
	hdr[0] |= len & 0xf;
	len >>= 4;
	for (i = 1; len != 0; i++){
		if (i >= bufsize)
			return got_error(GOT_ERR_NO_SPACE);
		hdr[i - 1] |= GOT_DELTA_SIZE_MORE;
		hdr[i] = len & GOT_DELTA_SIZE_VAL_MASK;
		len >>= GOT_DELTA_SIZE_SHIFT;
	}

	*hdrlen = i;
	return NULL;
}

static const struct got_error *
encodedelta(struct got_pack_meta *m, struct got_raw_object *o,
    off_t base_size, FILE *f)
{
	unsigned char buf[16], *bp;
	int i, j;
	off_t n;
	size_t w;
	struct got_delta_instruction *d;

	/* base object size */
	buf[0] = base_size & GOT_DELTA_SIZE_VAL_MASK;
	n = base_size >> GOT_DELTA_SIZE_SHIFT;
	for (i = 1; n > 0; i++) {
		buf[i - 1] |= GOT_DELTA_SIZE_MORE;
		buf[i] = n & GOT_DELTA_SIZE_VAL_MASK;
		n >>= GOT_DELTA_SIZE_SHIFT;
	}
	w = fwrite(buf, 1, i, f);
	if (w != i)
		return got_ferror(f, GOT_ERR_IO);

	/* target object size */
	buf[0] = o->size & GOT_DELTA_SIZE_VAL_MASK;
	n = o->size >> GOT_DELTA_SIZE_SHIFT;
	for (i = 1; n > 0; i++) {
		buf[i - 1] |= GOT_DELTA_SIZE_MORE;
		buf[i] = n & GOT_DELTA_SIZE_VAL_MASK;
		n >>= GOT_DELTA_SIZE_SHIFT;
	}
	w = fwrite(buf, 1, i, f);
	if (w != i)
		return got_ferror(f, GOT_ERR_IO);

	for (j = 0; j < m->ndeltas; j++) {
		d = &m->deltas[j];
		if (d->copy) {
			n = d->offset;
			bp = &buf[1];
			buf[0] = GOT_DELTA_BASE_COPY;
			for (i = 0; i < 4; i++) {
				/* DELTA_COPY_OFF1 ... DELTA_COPY_OFF4 */
				buf[0] |= 1 << i;
				*bp++ = n & 0xff;
				n >>= 8;
				if (n == 0)
					break;
			}

			n = d->len;
			if (n != GOT_DELTA_COPY_DEFAULT_LEN) {
				/* DELTA_COPY_LEN1 ... DELTA_COPY_LEN3 */
				for (i = 0; i < 3 && n > 0; i++) {
					buf[0] |= 1 << (i + 4);
					*bp++ = n & 0xff;
					n >>= 8;
				}
			}
			w = fwrite(buf, 1, bp - buf, f);
			if (w != bp - buf)
				return got_ferror(f, GOT_ERR_IO);
		} else {
			char content[128];
			size_t r;
			if (fseeko(o->f, o->hdrlen + d->offset, SEEK_SET) == -1)
				return got_error_from_errno("fseeko");
			n = 0;
			while (n != d->len) {
				buf[0] = (d->len - n < 127) ? d->len - n : 127;
				w = fwrite(buf, 1, 1, f);
				if (w != 1)
					return got_ferror(f, GOT_ERR_IO);
				r = fread(content, 1, buf[0], o->f);
				if (r != buf[0])
					return got_ferror(o->f, GOT_ERR_IO);
				w = fwrite(content, 1, buf[0], f);
				if (w != buf[0])
					return got_ferror(f, GOT_ERR_IO);
				n += buf[0];
			}
		}
	}

	return NULL;
}

static int
packoff(char *hdr, off_t off)
{
	int i, j;
	char rbuf[8];

	rbuf[0] = off & GOT_DELTA_SIZE_VAL_MASK;
	for (i = 1; (off >>= GOT_DELTA_SIZE_SHIFT) != 0; i++) {
		rbuf[i] = (--off & GOT_DELTA_SIZE_VAL_MASK) |
		    GOT_DELTA_SIZE_MORE;
	}

	j = 0;
	while (i > 0)
		hdr[j++] = rbuf[--i];
	return j;
}

static const struct got_error *
genpack(uint8_t *pack_sha1, FILE *packfile,
    struct got_pack_meta **meta, int nmeta, int nours,
    int use_offset_deltas, struct got_repository *repo,
    got_pack_progress_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	int i, nh;
	off_t nd;
	SHA1_CTX ctx;
	struct got_pack_meta *m;
	struct got_raw_object *raw = NULL;
	FILE *delta_file = NULL;
	char buf[32];
	size_t outlen, n;
	struct got_deflate_checksum csum;
	off_t packfile_size = 0;
	int outfd = -1;

	SHA1Init(&ctx);
	csum.output_sha1 = &ctx;
	csum.output_crc = NULL;

	err = hwrite(packfile, "PACK", 4, &ctx);
	if (err)
		return err;
	putbe32(buf, GOT_PACKFILE_VERSION);
	err = hwrite(packfile, buf, 4, &ctx);
	if (err)
		goto done;
	putbe32(buf, nmeta);
	err = hwrite(packfile, buf, 4, &ctx);
	if (err)
		goto done;
	qsort(meta, nmeta, sizeof(struct got_pack_meta *), write_order_cmp);
	for (i = 0; i < nmeta; i++) {
		if (progress_cb) {
			err = progress_cb(progress_arg, packfile_size, nours,
			    nmeta, nmeta, i);
			if (err)
				goto done;
		}
		m = meta[i];
		m->off = ftello(packfile);
		err = got_object_raw_open(&raw, &outfd, repo, &m->id, 8192);
		if (err)
			goto done;
		if (m->deltas == NULL) {
			err = packhdr(&nh, buf, sizeof(buf),
			    m->obj_type, raw->size);
			if (err)
				goto done;
			err = hwrite(packfile, buf, nh, &ctx);
			if (err)
				goto done;
			packfile_size += nh;
			if (fseeko(raw->f, raw->hdrlen, SEEK_SET) == -1) {
				err = got_error_from_errno("fseeko");
				goto done;
			}
			err = got_deflate_to_file(&outlen, raw->f, packfile,
			    &csum);
			if (err)
				goto done;
			packfile_size += outlen;
		} else {
			if (delta_file == NULL) {
				delta_file = got_opentemp();
				if (delta_file == NULL) {
					err = got_error_from_errno(
					    "got_opentemp");
					goto done;
				}
			}
			if (ftruncate(fileno(delta_file), 0L) == -1) {
				err = got_error_from_errno("ftruncate");
				goto done;
			}
			if (fseeko(delta_file, 0L, SEEK_SET) == -1) {
				err = got_error_from_errno("fseeko");
				goto done;
			}
			err = encodedelta(m, raw, m->prev->size, delta_file);
			if (err)
				goto done;
			nd = ftello(delta_file);
			if (fseeko(delta_file, 0L, SEEK_SET) == -1) {
				err = got_error_from_errno("fseeko");
				goto done;
			}
			if (use_offset_deltas && m->prev->off != 0) {
				err = packhdr(&nh, buf, sizeof(buf),
				    GOT_OBJ_TYPE_OFFSET_DELTA, nd);
				if (err)
					goto done;
				nh += packoff(buf + nh,
				    m->off - m->prev->off);
				err = hwrite(packfile, buf, nh, &ctx);
				if (err)
					goto done;
				packfile_size += nh;
			} else {
				err = packhdr(&nh, buf, sizeof(buf),
				    GOT_OBJ_TYPE_REF_DELTA, nd);
				err = hwrite(packfile, buf, nh, &ctx);
				if (err)
					goto done;
				packfile_size += nh;
				err = hwrite(packfile, m->prev->id.sha1,
				    sizeof(m->prev->id.sha1), &ctx);
				packfile_size += sizeof(m->prev->id.sha1);
				if (err)
					goto done;
			}
			err = got_deflate_to_file(&outlen, delta_file,
			    packfile, &csum);
			if (err)
				goto done;
			packfile_size += outlen;
		}
		got_object_raw_close(raw);
		raw = NULL;
	}
	SHA1Final(pack_sha1, &ctx);
	n = fwrite(pack_sha1, 1, SHA1_DIGEST_LENGTH, packfile);
	if (n != SHA1_DIGEST_LENGTH)
		err = got_ferror(packfile, GOT_ERR_IO);
	packfile_size += SHA1_DIGEST_LENGTH;
	packfile_size += sizeof(struct got_packfile_hdr);
	err = progress_cb(progress_arg, packfile_size, nours,
	    nmeta, nmeta, nmeta);
	if (err)
		goto done;
done:
	if (delta_file && fclose(delta_file) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (raw)
		got_object_raw_close(raw);
	if (outfd != -1 && close(outfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	return err;
}

const struct got_error *
got_pack_create(uint8_t *packsha1, FILE *packfile,
    struct got_object_id **theirs, int ntheirs,
    struct got_object_id **ours, int nours,
    struct got_repository *repo, int loose_obj_only, int allow_empty,
    got_pack_progress_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err;
	struct got_pack_meta **meta;
	int nmeta;

	err = read_meta(&meta, &nmeta, theirs, ntheirs, ours, nours, repo,
	    loose_obj_only, progress_cb, progress_arg, cancel_cb, cancel_arg);
	if (err)
		return err;

	if (nmeta == 0 && !allow_empty) {
		err = got_error(GOT_ERR_CANNOT_PACK);
		goto done;
	}
	if (nmeta > 0) {
		err = pick_deltas(meta, nmeta, nours, repo,
		    progress_cb, progress_arg, cancel_cb, cancel_arg);
		if (err)
			goto done;
	}

	err = genpack(packsha1, packfile, meta, nmeta, nours, 1, repo,
	    progress_cb, progress_arg, cancel_cb, cancel_arg);
	if (err)
		goto done;
done:
	free_nmeta(meta, nmeta);
	return err;
}
