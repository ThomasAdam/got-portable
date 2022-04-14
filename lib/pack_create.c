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
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <limits.h>
#include <zlib.h>

#if defined(__FreeBSD__)
#include <unistd.h>
#endif

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
#include "got_lib_ratelimit.h"

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

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
	unsigned char *delta_buf; /* if not encoded in delta cache file */
	off_t	delta_offset;	/* offset in delta cache file */
	off_t	delta_len;	/* encoded delta length */
	int	nchain;

	int	have_reused_delta;
	off_t   reused_delta_offset; /* offset of delta in reused pack file */
	struct got_object_id *base_obj_id;

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
	free(meta->path);
	meta->path = NULL;
	free(meta->delta_buf);
	meta->delta_buf = NULL;
	free(meta->base_obj_id);
	meta->base_obj_id = NULL;
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

static off_t
delta_size(struct got_delta_instruction *deltas, int ndeltas)
{
	int i;
	off_t size = 32;
	for (i = 0; i < ndeltas; i++) {
		if (deltas[i].copy)
			size += GOT_DELTA_SIZE_SHIFT;
		else
			size += deltas[i].len + 1;
	}
	return size;
}

static const struct got_error *
append(unsigned char **p, size_t *len, off_t *sz, void *seg, int nseg)
{
	char *n;

	if (*len + nseg >= *sz) {
		while (*len + nseg >= *sz)
			*sz += *sz / 2;
		n = realloc(*p, *sz);
		if (n == NULL)
			return got_error_from_errno("realloc");
		*p = n;
	}
	memcpy(*p + *len, seg, nseg);
	*len += nseg;
	return NULL;
}

static const struct got_error *
encode_delta_in_mem(struct got_pack_meta *m, struct got_raw_object *o,
    struct got_delta_instruction *deltas, int ndeltas,
    off_t delta_size, off_t base_size)
{
	const struct got_error *err;
	unsigned char buf[16], *bp;
	int i, j;
	size_t len = 0;
	off_t n;
	struct got_delta_instruction *d;

	m->delta_buf = malloc(delta_size);
	if (m->delta_buf == NULL)
		return got_error_from_errno("calloc");

	/* base object size */
	buf[0] = base_size & GOT_DELTA_SIZE_VAL_MASK;
	n = base_size >> GOT_DELTA_SIZE_SHIFT;
	for (i = 1; n > 0; i++) {
		buf[i - 1] |= GOT_DELTA_SIZE_MORE;
		buf[i] = n & GOT_DELTA_SIZE_VAL_MASK;
		n >>= GOT_DELTA_SIZE_SHIFT;
	}
	err = append(&m->delta_buf, &len, &delta_size, buf, i);
	if (err)
		return err;

	/* target object size */
	buf[0] = o->size & GOT_DELTA_SIZE_VAL_MASK;
	n = o->size >> GOT_DELTA_SIZE_SHIFT;
	for (i = 1; n > 0; i++) {
		buf[i - 1] |= GOT_DELTA_SIZE_MORE;
		buf[i] = n & GOT_DELTA_SIZE_VAL_MASK;
		n >>= GOT_DELTA_SIZE_SHIFT;
	}
	err = append(&m->delta_buf, &len, &delta_size, buf, i);
	if (err)
		return err;

	for (j = 0; j < ndeltas; j++) {
		d = &deltas[j];
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
			err = append(&m->delta_buf, &len, &delta_size,
			    buf, bp - buf);
			if (err)
				return err;
		} else if (o->f == NULL) {
			n = 0;
			while (n != d->len) {
				buf[0] = (d->len - n < 127) ? d->len - n : 127;
				err = append(&m->delta_buf, &len, &delta_size,
				    buf, 1);
				if (err)
					return err;
				err = append(&m->delta_buf, &len, &delta_size,
				    o->data + o->hdrlen + d->offset + n,
				    buf[0]);
				if (err)
					return err;
				n += buf[0];
			}
		} else {
			char content[128];
			size_t r;
			if (fseeko(o->f, o->hdrlen + d->offset, SEEK_SET) == -1)
				return got_error_from_errno("fseeko");
			n = 0;
			while (n != d->len) {
				buf[0] = (d->len - n < 127) ? d->len - n : 127;
				err = append(&m->delta_buf, &len, &delta_size,
				    buf, 1);
				if (err)
					return err;
				r = fread(content, 1, buf[0], o->f);
				if (r != buf[0])
					return got_ferror(o->f, GOT_ERR_IO);
				err = append(&m->delta_buf, &len, &delta_size,
				    content, buf[0]);
				if (err)
					return err;
				n += buf[0];
			}
		}
	}

	m->delta_len = len;
	return NULL;
}

static const struct got_error *
encode_delta(struct got_pack_meta *m, struct got_raw_object *o,
    struct got_delta_instruction *deltas, int ndeltas,
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

	for (j = 0; j < ndeltas; j++) {
		d = &deltas[j];
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
		} else if (o->f == NULL) {
			n = 0;
			while (n != d->len) {
				buf[0] = (d->len - n < 127) ? d->len - n : 127;
				w = fwrite(buf, 1, 1, f);
				if (w != 1)
					return got_ferror(f, GOT_ERR_IO);
				w = fwrite(o->data + o->hdrlen + d->offset + n,
				    1, buf[0], f);
				if (w != buf[0])
					return got_ferror(f, GOT_ERR_IO);
				n += buf[0];
			}
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

	m->delta_len = ftello(f) - m->delta_offset;
	return NULL;
}

static const struct got_error *
report_progress(got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, int ncolored, int nfound, int ntrees,
    off_t packfile_size, int ncommits, int nobj_total, int obj_deltify,
    int nobj_written)
{
	const struct got_error *err;
	int elapsed;

	if (progress_cb == NULL)
		return NULL;

	err = got_ratelimit_check(&elapsed, rl);
	if (err || !elapsed)
		return err;

	return progress_cb(progress_arg, ncolored, nfound, ntrees,
	    packfile_size, ncommits, nobj_total, obj_deltify, nobj_written);
}

static const struct got_error *
add_meta(struct got_pack_meta *m, struct got_pack_metavec *v)
{
	if (v->nmeta == v->metasz){
		size_t newsize = 2 * v->metasz;
		struct got_pack_meta **new;
		new = reallocarray(v->meta, newsize, sizeof(*new));
		if (new == NULL)
			return got_error_from_errno("reallocarray");
		v->meta = new;
		v->metasz = newsize; 
	}

	v->meta[v->nmeta++] = m;
	return NULL;
}

static const struct got_error *
reuse_delta(int idx, struct got_pack_meta *m, struct got_pack_metavec *v,
    struct got_object_idset *idset, struct got_pack *pack,
    struct got_packidx *packidx, int delta_cache_fd,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_pack_meta *base = NULL;
	struct got_object_id *base_obj_id = NULL;
	off_t delta_len = 0, delta_offset = 0, delta_cache_offset = 0;
	uint64_t base_size, result_size;

	if (m->have_reused_delta)
		return NULL;

	err = got_object_read_raw_delta(&base_size, &result_size, &delta_len,
	    &delta_offset, &delta_cache_offset, &base_obj_id, delta_cache_fd,
	    packidx, idx, &m->id, repo);
	if (err)
		return err;

	if (delta_offset + delta_len < delta_offset)
		return got_error(GOT_ERR_BAD_PACKFILE);

	base = got_object_idset_get(idset, base_obj_id);
	if (base == NULL)
		goto done;

	m->delta_len = delta_len;
	m->delta_offset = delta_cache_offset;
	m->prev = base;
	m->size = result_size;
	m->have_reused_delta = 1;
	m->reused_delta_offset = delta_offset;
	m->base_obj_id = base_obj_id;
	base_obj_id = NULL;
	err = add_meta(m, v);
done:
	free(base_obj_id);
	return err;
}

static const struct got_error *
find_pack_for_reuse(struct got_packidx **best_packidx,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_pathlist_entry *pe;
	const char *best_packidx_path = NULL;
	int nobj_max = 0;

	*best_packidx = NULL;

	TAILQ_FOREACH(pe, &repo->packidx_paths, entry) {
		const char *path_packidx = pe->path;
		struct got_packidx *packidx;
		int nobj;

		err = got_repo_get_packidx(&packidx, path_packidx, repo);
		if (err)
			break;

		nobj = be32toh(packidx->hdr.fanout_table[0xff]);
		if (nobj > nobj_max) {
			best_packidx_path = path_packidx;
			nobj_max = nobj;
		}
	}

	if (best_packidx_path) {
		err = got_repo_get_packidx(best_packidx, best_packidx_path,
		    repo);
	}

	return err;
}

struct search_deltas_arg {
	struct got_packidx *packidx;
	struct got_pack *pack;
	struct got_object_idset *idset;
	struct got_pack_metavec *v;
	int delta_cache_fd;
	struct got_repository *repo;
	got_pack_progress_cb progress_cb;
	void *progress_arg;
	struct got_ratelimit *rl;
	got_cancel_cb cancel_cb;
	void *cancel_arg;
	int ncolored;
	int nfound;
	int ntrees;
	int ncommits;
};

static const struct got_error *
search_delta_for_object(struct got_object_id *id, void *data, void *arg)
{
	const struct got_error *err;
	struct got_pack_meta *m = data;
	struct search_deltas_arg *a = arg;
	int obj_idx;
	struct got_object *obj = NULL;

	if (a->cancel_cb) {
		err = (*a->cancel_cb)(a->cancel_arg);
		if (err)
			return err;
	}

	if (!got_repo_check_packidx_bloom_filter(a->repo,
	    a->packidx->path_packidx, id))
		return NULL;

	obj_idx = got_packidx_get_object_idx(a->packidx, id);
	if (obj_idx == -1)
		return NULL;

	/* TODO:
	 * Opening and closing an object just to check its flags
	 * is a bit expensive. We could have an imsg which requests
	 * plain type/size information for an object without doing
	 * work such as traversing the object's entire delta chain
	 * to find the base object type, and other such info which
	 * we don't really need here.
	 */
	err = got_object_open_from_packfile(&obj, &m->id, a->pack,
	    a->packidx, obj_idx, a->repo);
	if (err)
		return err;

	if (obj->flags & GOT_OBJ_FLAG_DELTIFIED) {
		reuse_delta(obj_idx, m, a->v, a->idset, a->pack, a->packidx,
		    a->delta_cache_fd, a->repo);
		if (err)
			goto done;
		err = report_progress(a->progress_cb, a->progress_arg, a->rl,
		    a->ncolored, a->nfound, a->ntrees, 0L, a->ncommits,
		    got_object_idset_num_elements(a->idset), a->v->nmeta, 0);
	}
done:
	got_object_close(obj);
	return err;
}

static const struct got_error *
search_deltas(struct got_pack_metavec *v, struct got_object_idset *idset,
    int delta_cache_fd, int ncolored, int nfound, int ntrees, int ncommits,
    struct got_repository *repo,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	char *path_packfile = NULL;
	struct got_packidx *packidx;
	struct got_pack *pack;
	struct search_deltas_arg sda;

	err = find_pack_for_reuse(&packidx, repo);
	if (err)
		return err;

	if (packidx == NULL)
		return NULL;

	err = got_packidx_get_packfile_path(&path_packfile,
	    packidx->path_packidx);
	if (err)
		return err;

	pack = got_repo_get_cached_pack(repo, path_packfile);
	if (pack == NULL) {
		err = got_repo_cache_pack(&pack, repo, path_packfile, packidx);
		if (err)
			goto done;
	}

	sda.packidx = packidx;
	sda.pack = pack;
	sda.idset = idset;
	sda.v = v;
	sda.delta_cache_fd = delta_cache_fd;
	sda.repo = repo;
	sda.progress_cb = progress_cb;
	sda.progress_arg = progress_arg;
	sda.rl = rl;
	sda.cancel_cb = cancel_cb;
	sda.cancel_arg = cancel_arg;
	sda.ncolored = ncolored;
	sda.nfound = nfound;
	sda.ntrees = ntrees;
	sda.ncommits = ncommits;
	err = got_object_idset_for_each(idset, search_delta_for_object, &sda);
done:
	free(path_packfile);
	return err;
}

static const struct got_error *
pick_deltas(struct got_pack_meta **meta, int nmeta, int ncolored,
    int nfound, int ntrees, int ncommits, int nreused, FILE *delta_cache,
    struct got_repository *repo,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_pack_meta *m = NULL, *base = NULL;
	struct got_raw_object *raw = NULL, *base_raw = NULL;
	struct got_delta_instruction *deltas = NULL, *best_deltas = NULL;
	int i, j, ndeltas, best_ndeltas;
	off_t size, best_size;
	const int max_base_candidates = 3;
	size_t delta_memsize = 0;
	const size_t max_delta_memsize = 25 * GOT_DELTA_RESULT_SIZE_CACHED_MAX;
	int outfd = -1;

	qsort(meta, nmeta, sizeof(struct got_pack_meta *), delta_order_cmp);
	for (i = 0; i < nmeta; i++) {
		if (cancel_cb) {
			err = (*cancel_cb)(cancel_arg);
			if (err)
				break;
		}
		err = report_progress(progress_cb, progress_arg, rl,
		    ncolored, nfound, ntrees, 0L, ncommits, nreused + nmeta,
		    nreused + i, 0);
		if (err)
			goto done;
		m = meta[i];

		if (m->obj_type == GOT_OBJ_TYPE_COMMIT ||
		    m->obj_type == GOT_OBJ_TYPE_TAG)
			continue;

		err = got_object_raw_open(&raw, &outfd, repo, &m->id);
		if (err)
			goto done;
		m->size = raw->size;

		if (raw->f == NULL) {
			err = got_deltify_init_mem(&m->dtab, raw->data,
			    raw->hdrlen, raw->size + raw->hdrlen);
		} else {
			err = got_deltify_init(&m->dtab, raw->f, raw->hdrlen,
			    raw->size + raw->hdrlen);
		}
		if (err)
			goto done;

		if (i > max_base_candidates) {
			struct got_pack_meta *n = NULL;
			n = meta[i - (max_base_candidates + 1)];
			got_deltify_free(n->dtab);
			n->dtab = NULL;
		}

		best_size = raw->size;
		best_ndeltas = 0;
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
			    &base->id);
			if (err)
				goto done;

			if (raw->f == NULL && base_raw->f == NULL) {
				err = got_deltify_mem_mem(&deltas, &ndeltas,
				    raw->data, raw->hdrlen,
				    raw->size + raw->hdrlen,
				    base->dtab, base_raw->data,
				    base_raw->hdrlen,
				    base_raw->size + base_raw->hdrlen);
			} else if (raw->f == NULL) {
				err = got_deltify_mem_file(&deltas, &ndeltas,
				    raw->data, raw->hdrlen,
				    raw->size + raw->hdrlen,
				    base->dtab, base_raw->f,
				    base_raw->hdrlen,
				    base_raw->size + base_raw->hdrlen);
			} else if (base_raw->f == NULL) {
				err = got_deltify_file_mem(&deltas, &ndeltas,
				    raw->f, raw->hdrlen,
				    raw->size + raw->hdrlen,
				    base->dtab, base_raw->data,
				    base_raw->hdrlen,
				    base_raw->size + base_raw->hdrlen);
			} else {
				err = got_deltify(&deltas, &ndeltas,
				    raw->f, raw->hdrlen,
				    raw->size + raw->hdrlen,
				    base->dtab, base_raw->f, base_raw->hdrlen,
				    base_raw->size + base_raw->hdrlen);
			}
			got_object_raw_close(base_raw);
			base_raw = NULL;
			if (err)
				goto done;

			size = delta_size(deltas, ndeltas);
			if (size + 32 < best_size){
				/*
				 * if we already picked a best delta,
				 * replace it.
				 */
				best_size = size;
				free(best_deltas);
				best_deltas = deltas;
				best_ndeltas = ndeltas;
				deltas = NULL;
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

		if (best_ndeltas > 0) {
			if (best_size <= GOT_DELTA_RESULT_SIZE_CACHED_MAX &&
			    delta_memsize + best_size <= max_delta_memsize) {
				delta_memsize += best_size;
				err = encode_delta_in_mem(m, raw, best_deltas,
				    best_ndeltas, best_size, m->prev->size);
			} else {
				m->delta_offset = ftello(delta_cache);
				/*
				 * TODO:
				 * Storing compressed delta data in the delta
				 * cache file would probably be more efficient
				 * than writing uncompressed delta data here
				 * and compressing it while writing the pack
				 * file. This would also allow for reusing
				 * deltas in their compressed form.
				 */
				err = encode_delta(m, raw, best_deltas,
				    best_ndeltas, m->prev->size, delta_cache);
			}
			free(best_deltas);
			best_deltas = NULL;
			best_ndeltas = 0;
			if (err)
				goto done;
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
	free(deltas);
	free(best_deltas);
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

static const struct got_error *
add_object(int want_meta, struct got_object_idset *idset,
    struct got_object_id *id, const char *path, int obj_type,
    time_t mtime, int loose_obj_only, struct got_repository *repo,
    int *ncolored, int *nfound, int *ntrees,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl)
{
	const struct got_error *err;
	struct got_pack_meta *m = NULL;

	if (loose_obj_only) {
		int is_packed;
		err = search_packidx(&is_packed, id, repo);
		if (err)
			return err;
		if (is_packed && want_meta)
			return NULL;
	}

	if (want_meta) {
		err = alloc_meta(&m, id, path, obj_type, mtime);
		if (err)
			return err;

		(*nfound)++;
		err = report_progress(progress_cb, progress_arg, rl,
		    *ncolored, *nfound, *ntrees, 0L, 0, 0, 0, 0);
		if (err) {
			clear_meta(m);
			free(m);
			return err;
		}
	}

	err = got_object_idset_add(idset, id, m);
	if (err) {
		clear_meta(m);
		free(m);
	}
	return err;
}

static const struct got_error *
load_tree_entries(struct got_object_id_queue *ids, int want_meta,
    struct got_object_idset *idset, struct got_object_id *tree_id,
    const char *dpath, time_t mtime, struct got_repository *repo,
    int loose_obj_only, int *ncolored, int *nfound, int *ntrees,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err;
	struct got_tree_object *tree;
	char *p = NULL;
	int i;

	err = got_object_open_as_tree(&tree, repo, tree_id);
	if (err)
		return err;

	(*ntrees)++;
	err = report_progress(progress_cb, progress_arg, rl,
	    *ncolored, *nfound, *ntrees, 0L, 0, 0, 0, 0);
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
			err = add_object(want_meta, idset, id, p,
			    GOT_OBJ_TYPE_BLOB, mtime, loose_obj_only, repo,
			    ncolored, nfound, ntrees,
			    progress_cb, progress_arg, rl);
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
load_tree(int want_meta, struct got_object_idset *idset,
    struct got_object_id *tree_id, const char *dpath, time_t mtime,
    struct got_repository *repo, int loose_obj_only,
    int *ncolored, int *nfound, int *ntrees,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg)
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

		err = add_object(want_meta, idset, qid->id, dpath,
		    GOT_OBJ_TYPE_TREE, mtime, loose_obj_only, repo,
		    ncolored, nfound, ntrees, progress_cb, progress_arg, rl);
		if (err) {
			got_object_qid_free(qid);
			break;
		}

		err = load_tree_entries(&tree_ids, want_meta, idset, qid->id,
		    dpath, mtime, repo, loose_obj_only, ncolored, nfound,
		    ntrees, progress_cb, progress_arg, rl,
		    cancel_cb, cancel_arg);
		got_object_qid_free(qid);
		if (err)
			break;
	}

	got_object_id_queue_free(&tree_ids);
	return err;
}

static const struct got_error *
load_commit(int want_meta, struct got_object_idset *idset,
    struct got_object_id *id, struct got_repository *repo, int loose_obj_only,
    int *ncolored, int *nfound, int *ntrees,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg)
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
		if (is_packed && want_meta)
			return NULL;
	}

	err = got_object_open_as_commit(&commit, repo, id);
	if (err)
		return err;

	err = add_object(want_meta, idset, id, "", GOT_OBJ_TYPE_COMMIT,
	    got_object_commit_get_committer_time(commit),
	    loose_obj_only, repo,
	    ncolored, nfound, ntrees, progress_cb, progress_arg, rl);
	if (err)
		goto done;

	err = load_tree(want_meta, idset, got_object_commit_get_tree_id(commit),
	    "", got_object_commit_get_committer_time(commit),
	    repo, loose_obj_only, ncolored, nfound, ntrees,
	    progress_cb, progress_arg, rl, cancel_cb, cancel_arg);
done:
	got_object_commit_close(commit);
	return err;
}

static const struct got_error *
load_tag(int want_meta, struct got_object_idset *idset,
    struct got_object_id *id, struct got_repository *repo, int loose_obj_only,
    int *ncolored, int *nfound, int *ntrees,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg)
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
		if (is_packed && want_meta)
			return NULL;
	}

	err = got_object_open_as_tag(&tag, repo, id);
	if (err)
		return err;

	err = add_object(want_meta, idset, id, "", GOT_OBJ_TYPE_TAG,
	    got_object_tag_get_tagger_time(tag), loose_obj_only, repo,
	    ncolored, nfound, ntrees, progress_cb, progress_arg, rl);
	if (err)
		goto done;

	switch (got_object_tag_get_object_type(tag)) {
	case GOT_OBJ_TYPE_COMMIT:
		err = load_commit(want_meta, idset,
		    got_object_tag_get_object_id(tag), repo, loose_obj_only,
		    ncolored, nfound, ntrees, progress_cb, progress_arg, rl,
		    cancel_cb, cancel_arg);
		break;
	case GOT_OBJ_TYPE_TREE:
		err = load_tree(want_meta, idset,
		    got_object_tag_get_object_id(tag), "",
		    got_object_tag_get_tagger_time(tag), repo, loose_obj_only,
		    ncolored, nfound, ntrees, progress_cb, progress_arg, rl,
		    cancel_cb, cancel_arg);
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

		err = got_object_idset_add(drop, qid->id, NULL);
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
queue_commit_or_tag_id(struct got_object_id *id, int color,
    struct got_object_id_queue *ids, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_tag_object *tag = NULL;
	int obj_type;

	err = got_object_get_type(&obj_type, repo, id);
	if (err)
		return err;

	if (obj_type == GOT_OBJ_TYPE_TAG) {
		err = got_object_open_as_tag(&tag, repo, id);
		if (err)
			return err;
		obj_type = got_object_tag_get_object_type(tag);
		id = got_object_tag_get_object_id(tag);
	}

	if (obj_type == GOT_OBJ_TYPE_COMMIT) {
		err = queue_commit_id(ids, id, color, repo);
		if (err)
			goto done;
	}
done:
	if (tag)
		got_object_tag_close(tag);
	return err;
}

static const struct got_error *
color_commits(int *ncolored, struct got_object_id_queue *ids,
    struct got_object_idset *keep, struct got_object_idset *drop,
    struct got_repository *repo,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_commit_object *commit = NULL;
	struct got_object_qid *qid;

	while (!STAILQ_EMPTY(ids)) {
		int qcolor, ncolor;

		if (cancel_cb) {
			err = cancel_cb(cancel_arg);
			if (err)
				break;
		}

		qid = STAILQ_FIRST(ids);
		qcolor = *((int *)qid->data);

		if (got_object_idset_contains(drop, qid->id))
			ncolor = COLOR_DROP;
		else if (got_object_idset_contains(keep, qid->id))
			ncolor = COLOR_KEEP;
		else
			ncolor = COLOR_BLANK;

		(*ncolored)++;
		err = report_progress(progress_cb, progress_arg, rl,
		    *ncolored, 0, 0, 0L, 0, 0, 0, 0);
		if (err)
			break;

		if (ncolor == COLOR_DROP || (ncolor == COLOR_KEEP &&
		    qcolor == COLOR_KEEP)) {
			STAILQ_REMOVE_HEAD(ids, entry);
			got_object_qid_free(qid);
			continue;
		}

		if (ncolor == COLOR_KEEP && qcolor == COLOR_DROP) {
			err = drop_commit(keep, drop, qid->id, repo,
			    cancel_cb, cancel_arg);
			if (err)
				break;
		} else if (ncolor == COLOR_BLANK) {
			struct got_commit_object *commit;
			const struct got_object_id_queue *parents;
			struct got_object_qid *pid;

			if (qcolor == COLOR_KEEP)
				err = got_object_idset_add(keep, qid->id, NULL);
			else
				err = got_object_idset_add(drop, qid->id, NULL);
			if (err)
				break;

			err = got_object_open_as_commit(&commit, repo, qid->id);
			if (err)
				break;

			parents = got_object_commit_get_parent_ids(commit);
			if (parents) {
				STAILQ_FOREACH(pid, parents, entry) {
					err = queue_commit_id(ids, pid->id,
					    qcolor, repo);
					if (err)
						break;
				}
			}
			got_object_commit_close(commit);
			commit = NULL;
		} else {
			/* should not happen */
			err = got_error_fmt(GOT_ERR_NOT_IMPL,
			    "%s ncolor=%d qcolor=%d", __func__, ncolor, qcolor);
			break;
		}

		STAILQ_REMOVE_HEAD(ids, entry);
		got_object_qid_free(qid);
	}

	if (commit)
		got_object_commit_close(commit);
	return err;
}

static const struct got_error *
findtwixt(struct got_object_id ***res, int *nres, int *ncolored,
    struct got_object_id **head, int nhead,
    struct got_object_id **tail, int ntail,
    struct got_repository *repo,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_object_id_queue ids;
	struct got_object_idset *keep, *drop;
	int i, nkeep;

	STAILQ_INIT(&ids);
	*res = NULL;
	*nres = 0;
	*ncolored = 0;

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
		err = queue_commit_or_tag_id(id, COLOR_KEEP, &ids, repo);
		if (err)
			goto done;
	}		

	for (i = 0; i < ntail; i++) {
		struct got_object_id *id = tail[i];
		if (id == NULL)
			continue;
		err = queue_commit_or_tag_id(id, COLOR_DROP, &ids, repo);
		if (err)
			goto done;
	}

	err = color_commits(ncolored, &ids, keep, drop, repo,
	    progress_cb, progress_arg, rl, cancel_cb, cancel_arg);
	if (err)
		goto done;

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
load_object_ids(int *ncolored, int *nfound, int *ntrees,
    struct got_object_idset *idset, struct got_object_id **theirs, int ntheirs,
    struct got_object_id **ours, int nours, struct got_repository *repo,
    int loose_obj_only, got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_object_id **ids = NULL;
	int i, nobj = 0, obj_type;

	*ncolored = 0;
	*nfound = 0;
	*ntrees = 0;

	err = findtwixt(&ids, &nobj, ncolored, ours, nours, theirs, ntheirs,
	    repo, progress_cb, progress_arg, rl, cancel_cb, cancel_arg);
	if (err || nobj == 0)
		goto done;

	for (i = 0; i < ntheirs; i++) {
		struct got_object_id *id = theirs[i];
		if (id == NULL)
			continue;
		err = got_object_get_type(&obj_type, repo, id);
		if (err)
			return err;
		if (obj_type == GOT_OBJ_TYPE_COMMIT) {
			err = load_commit(0, idset, id, repo,
			    loose_obj_only, ncolored, nfound, ntrees,
			    progress_cb, progress_arg, rl,
			    cancel_cb, cancel_arg);
			if (err)
				goto done;
		} else if (obj_type == GOT_OBJ_TYPE_TAG) {
			err = load_tag(0, idset, id, repo,
			    loose_obj_only, ncolored, nfound, ntrees,
			    progress_cb, progress_arg, rl,
			    cancel_cb, cancel_arg);
			if (err)
				goto done;
		}
	}

	for (i = 0; i < nobj; i++) {
		err = load_commit(1, idset, ids[i], repo, loose_obj_only,
		    ncolored, nfound, ntrees, progress_cb, progress_arg, rl,
		    cancel_cb, cancel_arg);
		if (err)
			goto done;
	}

	for (i = 0; i < nours; i++) {
		struct got_object_id *id = ours[i];
		struct got_pack_meta *m;
		if (id == NULL)
			continue;
		m = got_object_idset_get(idset, id);
		if (m == NULL) {
			err = got_object_get_type(&obj_type, repo, id);
			if (err)
				goto done;
		} else
			obj_type = m->obj_type;
		if (obj_type != GOT_OBJ_TYPE_TAG)
			continue;
		err = load_tag(1, idset, id, repo, loose_obj_only,
		    ncolored, nfound, ntrees, progress_cb, progress_arg, rl,
		    cancel_cb, cancel_arg);
		if (err)
			goto done;
	}
done:
	for (i = 0; i < nobj; i++) {
		free(ids[i]);
	}
	free(ids);
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

static int
reuse_write_order_cmp(const void *pa, const void *pb)
{
	struct got_pack_meta *a, *b;

	a = *(struct got_pack_meta **)pa;
	b = *(struct got_pack_meta **)pb;

	if (a->reused_delta_offset < b->reused_delta_offset)
		return -1;
	if (a->reused_delta_offset > b->reused_delta_offset)
		return 1;
	return 0;
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
deltahdr(off_t *packfile_size, SHA1_CTX *ctx, FILE *packfile,
    struct got_pack_meta *m)
{
	const struct got_error *err;
	char buf[32];
	int nh;

	if (m->prev->off != 0) {
		err = packhdr(&nh, buf, sizeof(buf),
		    GOT_OBJ_TYPE_OFFSET_DELTA, m->delta_len);
		if (err)
			return err;
		nh += packoff(buf + nh, m->off - m->prev->off);
		err = hwrite(packfile, buf, nh, ctx);
		if (err)
			return err;
		*packfile_size += nh;
	} else {
		err = packhdr(&nh, buf, sizeof(buf),
		    GOT_OBJ_TYPE_REF_DELTA, m->delta_len);
		if (err)
			return err;
		err = hwrite(packfile, buf, nh, ctx);
		if (err)
			return err;
		*packfile_size += nh;
		err = hwrite(packfile, m->prev->id.sha1,
		    sizeof(m->prev->id.sha1), ctx);
		if (err)
			return err;
		*packfile_size += sizeof(m->prev->id.sha1);
	}

	return NULL;
}

static const struct got_error *
write_packed_object(off_t *packfile_size, FILE *packfile,
    FILE *delta_cache, struct got_pack_meta *m, int *outfd,
    SHA1_CTX *ctx, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_deflate_checksum csum;
	char buf[32];
	int nh;
	struct got_raw_object *raw = NULL;
	off_t outlen;

	csum.output_sha1 = ctx;
	csum.output_crc = NULL;

	m->off = ftello(packfile);
	if (m->delta_len == 0) {
		err = got_object_raw_open(&raw, outfd, repo, &m->id);
		if (err)
			goto done;
		err = packhdr(&nh, buf, sizeof(buf),
		    m->obj_type, raw->size);
		if (err)
			goto done;
		err = hwrite(packfile, buf, nh, ctx);
		if (err)
			goto done;
		*packfile_size += nh;
		if (raw->f == NULL) {
			err = got_deflate_to_file_mmap(&outlen,
			    raw->data + raw->hdrlen, 0, raw->size,
			    packfile, &csum);
			if (err)
				goto done;
		} else {
			if (fseeko(raw->f, raw->hdrlen, SEEK_SET)
			    == -1) {
				err = got_error_from_errno("fseeko");
				goto done;
			}
			err = got_deflate_to_file(&outlen, raw->f,
			    raw->size, packfile, &csum);
			if (err)
				goto done;
		}
		*packfile_size += outlen;
		got_object_raw_close(raw);
		raw = NULL;
	} else if (m->delta_buf) {
		err = deltahdr(packfile_size, ctx, packfile, m);
		if (err)
			goto done;
		err = got_deflate_to_file_mmap(&outlen,
		    m->delta_buf, 0, m->delta_len, packfile, &csum);
		if (err)
			goto done;
		*packfile_size += outlen;
		free(m->delta_buf);
		m->delta_buf = NULL;
	} else {
		if (fseeko(delta_cache, m->delta_offset, SEEK_SET)
		    == -1) {
			err = got_error_from_errno("fseeko");
			goto done;
		}
		err = deltahdr(packfile_size, ctx, packfile, m);
		if (err)
			goto done;
		err = got_deflate_to_file(&outlen, delta_cache,
		    m->delta_len, packfile, &csum);
		if (err)
			goto done;
		*packfile_size += outlen;
	}
done:
	if (raw)
		got_object_raw_close(raw);
	return err;
}

static const struct got_error *
genpack(uint8_t *pack_sha1, FILE *packfile, FILE *delta_cache,
    struct got_pack_meta **deltify, int ndeltify,
    struct got_pack_meta **reuse, int nreuse,
    int ncolored, int nfound, int ntrees, int nours,
    struct got_repository *repo,
    got_pack_progress_cb progress_cb, void *progress_arg,
    struct got_ratelimit *rl,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	int i;
	SHA1_CTX ctx;
	struct got_pack_meta *m;
	char buf[32];
	size_t n;
	off_t packfile_size = 0;
	int outfd = -1;

	SHA1Init(&ctx);

	err = hwrite(packfile, "PACK", 4, &ctx);
	if (err)
		return err;
	putbe32(buf, GOT_PACKFILE_VERSION);
	err = hwrite(packfile, buf, 4, &ctx);
	if (err)
		goto done;
	putbe32(buf, ndeltify + nreuse);
	err = hwrite(packfile, buf, 4, &ctx);
	if (err)
		goto done;

	qsort(deltify, ndeltify, sizeof(struct got_pack_meta *),
	    write_order_cmp);
	for (i = 0; i < ndeltify; i++) {
		err = report_progress(progress_cb, progress_arg, rl,
		    ncolored, nfound, ntrees, packfile_size, nours,
		    ndeltify + nreuse, ndeltify + nreuse, i);
		if (err)
			goto done;
		m = deltify[i];
		err = write_packed_object(&packfile_size, packfile,
		    delta_cache, m, &outfd, &ctx, repo);
		if (err)
			goto done;
	}

	qsort(reuse, nreuse, sizeof(struct got_pack_meta *),
	    reuse_write_order_cmp);
	for (i = 0; i < nreuse; i++) {
		err = report_progress(progress_cb, progress_arg, rl,
		    ncolored, nfound, ntrees, packfile_size, nours,
		    ndeltify + nreuse, ndeltify + nreuse, ndeltify + i);
		if (err)
			goto done;
		m = reuse[i];
		err = write_packed_object(&packfile_size, packfile,
		    delta_cache, m, &outfd, &ctx, repo);
		if (err)
			goto done;
	}

	SHA1Final(pack_sha1, &ctx);
	n = fwrite(pack_sha1, 1, SHA1_DIGEST_LENGTH, packfile);
	if (n != SHA1_DIGEST_LENGTH)
		err = got_ferror(packfile, GOT_ERR_IO);
	packfile_size += SHA1_DIGEST_LENGTH;
	packfile_size += sizeof(struct got_packfile_hdr);
	if (progress_cb) {
		err = progress_cb(progress_arg, ncolored, nfound, ntrees,
		    packfile_size, nours, ndeltify + nreuse,
		    ndeltify + nreuse, ndeltify + nreuse);
		if (err)
			goto done;
	}
done:
	if (outfd != -1 && close(outfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	return err;
}

static const struct got_error *
remove_unused_object(struct got_object_idset_element *entry, void *arg)
{
	struct got_object_idset *idset = arg;

	if (got_object_idset_get_element_data(entry) == NULL)
		got_object_idset_remove_element(idset, entry);

	return NULL;
}

static const struct got_error *
remove_reused_object(struct got_object_idset_element *entry, void *arg)
{
	struct got_object_idset *idset = arg;
	struct got_pack_meta *m;

	m = got_object_idset_get_element_data(entry);
	if (m->have_reused_delta)
		got_object_idset_remove_element(idset, entry);

	return NULL;
}

static const struct got_error *
add_meta_idset_cb(struct got_object_id *id, void *data, void *arg)
{
	struct got_pack_meta *m = data;
	struct got_pack_metavec *v = arg;

	return add_meta(m, v);
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
	int delta_cache_fd = -1;
	FILE *delta_cache = NULL;
	struct got_object_idset *idset;
	struct got_ratelimit rl;
	struct got_pack_metavec deltify, reuse;
	int ncolored = 0, nfound = 0, ntrees = 0;

	memset(&deltify, 0, sizeof(deltify));
	memset(&reuse, 0, sizeof(reuse));

	got_ratelimit_init(&rl, 0, 500);

	idset = got_object_idset_alloc();
	if (idset == NULL)
		return got_error_from_errno("got_object_idset_alloc");

	err = load_object_ids(&ncolored, &nfound, &ntrees, idset, theirs,
	    ntheirs, ours, nours, repo, loose_obj_only,
	    progress_cb, progress_arg, &rl, cancel_cb, cancel_arg);
	if (err)
		return err;

	err = got_object_idset_for_each_element(idset,
	    remove_unused_object, idset);
	if (err)
		goto done;

	if (progress_cb) {
		err = progress_cb(progress_arg, ncolored, nfound, ntrees,
		    0L, nours, got_object_idset_num_elements(idset), 0, 0);
		if (err)
			goto done;
	}

	if (got_object_idset_num_elements(idset) == 0 && !allow_empty) {
		err = got_error(GOT_ERR_CANNOT_PACK);
		goto done;
	}

	delta_cache_fd = got_opentempfd();
	if (delta_cache_fd == -1) {
		err = got_error_from_errno("got_opentemp");
		goto done;
	}

	reuse.metasz = 64;
	reuse.meta = calloc(reuse.metasz,
	    sizeof(struct got_pack_meta *));
	if (reuse.meta == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}

	err = search_deltas(&reuse, idset, delta_cache_fd, ncolored, nfound,
	    ntrees, nours, repo, progress_cb, progress_arg, &rl,
	    cancel_cb, cancel_arg);
	if (err)
		goto done;
	if (reuse.nmeta > 0) {
		err = got_object_idset_for_each_element(idset,
		    remove_reused_object, idset);
		if (err)
			goto done;
	}

	delta_cache = fdopen(delta_cache_fd, "a+");
	if (delta_cache == NULL) {
		err = got_error_from_errno("fdopen");
		goto done;
	}
	delta_cache_fd = -1;

	if (fseeko(delta_cache, 0L, SEEK_END) == -1) {
		err = got_error_from_errno("fseeko");
		goto done;
	}

	deltify.meta = calloc(got_object_idset_num_elements(idset),
	    sizeof(struct got_pack_meta *));
	if (deltify.meta == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}
	deltify.metasz = got_object_idset_num_elements(idset);

	err = got_object_idset_for_each(idset, add_meta_idset_cb, &deltify);
	if (err)
		goto done;
	if (deltify.nmeta > 0) {
		err = pick_deltas(deltify.meta, deltify.nmeta, ncolored,
		    nfound, ntrees, nours, reuse.nmeta, delta_cache, repo,
		    progress_cb, progress_arg, &rl, cancel_cb, cancel_arg);
		if (err)
			goto done;
		if (fseeko(delta_cache, 0L, SEEK_SET) == -1) {
			err = got_error_from_errno("fseeko");
			goto done;
		}
	}

	err = genpack(packsha1, packfile, delta_cache, deltify.meta,
	    deltify.nmeta, reuse.meta, reuse.nmeta, ncolored, nfound, ntrees,
	    nours, repo, progress_cb, progress_arg, &rl,
	    cancel_cb, cancel_arg);
	if (err)
		goto done;
done:
	free_nmeta(deltify.meta, deltify.nmeta);
	free_nmeta(reuse.meta, reuse.nmeta);
	got_object_idset_free(idset);
	if (delta_cache_fd != -1 && close(delta_cache_fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (delta_cache && fclose(delta_cache) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	return err;
}
