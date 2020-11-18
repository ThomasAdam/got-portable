/*
 * Copyright (c) 2018, 2019, 2020 Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2020 Neels Hofmeyr <neels@hofmeyr.de>
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
#include <sys/mman.h>
#include <sys/stat.h>

#include <sha1.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <limits.h>
#include <util.h>
#include <zlib.h>

#include "got_error.h"
#include "got_object.h"
#include "got_cancel.h"
#include "got_blame.h"
#include "got_commit_graph.h"
#include "got_opentemp.h"

#include "got_lib_inflate.h"
#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_diff.h"

#ifndef MAX
#define	MAX(_a,_b) ((_a) > (_b) ? (_a) : (_b))
#endif

struct got_blame_line {
	int annotated;
	struct got_object_id id;
};

struct got_blame {
	FILE *f;
	off_t size;
	struct diff_config *cfg;
	size_t filesize;
	int nlines;
	int nannotated;
	struct got_blame_line *lines; /* one per line */
	off_t *line_offsets;		/* one per line */
	int ncommits;

	/*
	 * Map line numbers of an older version of the file to valid line
	 * numbers in blame->f. This map is updated with each commit we
	 * traverse throughout the file's history.
	 * Lines mapped to -1 do not correspond to any line in blame->f.
	 */
	int *linemap2;
	int nlines2;
};

static const struct got_error *
annotate_line(struct got_blame *blame, int lineno, struct got_object_id *id,
    const struct got_error *(*cb)(void *, int, int, struct got_object_id *),
    void *arg)
{
	const struct got_error *err = NULL;
	struct got_blame_line *line;

	if (lineno < 0 || lineno >= blame->nlines)
		return NULL;

	line = &blame->lines[lineno];
	if (line->annotated)
		return NULL;

	memcpy(&line->id, id, sizeof(line->id));
	line->annotated = 1;
	blame->nannotated++;
	if (cb)
		err = cb(arg, blame->nlines, lineno + 1, id);
	return err;
}

static const struct got_error *
blame_changes(struct got_blame *blame, int *linemap1,
    struct diff_result *diff_result, struct got_object_id *commit_id,
    const struct got_error *(*cb)(void *, int, int, struct got_object_id *),
    void *arg)
{
	const struct got_error *err = NULL;
	int i;
	int idx1 = 0, idx2 = 0;

	for (i = 0; i < diff_result->chunks.len &&
	    blame->nannotated < blame->nlines; i++) {
		struct diff_chunk *c = diff_chunk_get(diff_result, i);
		unsigned int left_start, left_count;
		unsigned int right_start, right_count;
		int j;

		/*
		 * We do not need to worry about idx1/idx2 growing out
		 * of bounds because the diff implementation ensures
		 * that chunk ranges never exceed the number of lines
		 * in the left/right input files.
		 */
		left_start = diff_chunk_get_left_start(c, diff_result, 0);
		left_count = diff_chunk_get_left_count(c);
		right_start = diff_chunk_get_right_start(c, diff_result, 0);
		right_count = diff_chunk_get_right_count(c);

		if (left_count == right_count) {
			for (j = 0; j < left_count; j++) {
				linemap1[idx1++] = blame->linemap2[idx2++];
			}
			continue;
		}

		if (right_count == 0) {
			for (j = 0; j < left_count; j++) {
				linemap1[idx1++] = -1;
			}
			continue;
		}

		for (j = 0; j < right_count; j++) {
			int ln = blame->linemap2[idx2++];
			err = annotate_line(blame, ln, commit_id, cb, arg);
			if (err)
				return err;
			if (blame->nlines == blame->nannotated)
				break;
		}
	}

	return NULL;
}

static const struct got_error *
blame_commit(struct got_blame *blame, struct got_object_id *id,
    const char *path, struct got_repository *repo,
    const struct got_error *(*cb)(void *, int, int, struct got_object_id *),
    void *arg)
{
	const struct got_error *err = NULL;
	struct got_commit_object *commit = NULL;
	struct got_object_qid *pid = NULL;
	struct got_object_id *blob_id = NULL, *pblob_id = NULL;
	struct got_blob_object *blob = NULL, *pblob = NULL;
	struct got_diffreg_result *diffreg_result = NULL;
	FILE *f1 = NULL, *f2 = NULL;
	size_t size1, size2;
	int nlines1, nlines2;
	int *linemap1 = NULL;

	err = got_object_open_as_commit(&commit, repo, id);
	if (err)
		return err;

	pid = SIMPLEQ_FIRST(got_object_commit_get_parent_ids(commit));
	if (pid == NULL) {
		got_object_commit_close(commit);
		return NULL;
	}

	err = got_object_id_by_path(&blob_id, repo, id, path);
	if (err) {
		if (err->code == GOT_ERR_NO_TREE_ENTRY)
			err = NULL;
		goto done;
	}

	err = got_object_open_as_blob(&blob, repo, blob_id, 8192);
	if (err)
		goto done;

	f2 = got_opentemp();
	if (f2 == NULL) {
		err = got_error_from_errno("got_opentemp");
		goto done;
	}
	err = got_object_blob_dump_to_file(&size2, &nlines2, NULL,
	    f2, blob);
	if (err)
		goto done;

	err = got_object_id_by_path(&pblob_id, repo, pid->id, path);
	if (err) {
		if (err->code == GOT_ERR_NO_TREE_ENTRY)
			err = NULL;
		goto done;
	}

	err = got_object_open_as_blob(&pblob, repo, pblob_id, 8192);
	if (err)
		goto done;

	f1 = got_opentemp();
	if (f1 == NULL) {
		err = got_error_from_errno("got_opentemp");
		goto done;
	}
	err = got_object_blob_dump_to_file(&size1, &nlines1, NULL, f1, pblob);
	if (err)
		goto done;

	err = got_diff_files(&diffreg_result, f1, "", f2, "",
	    0, 0, NULL);
	if (err)
		goto done;
	if (diffreg_result->result->chunks.len > 0) {
		if (nlines1 > 0) {
			linemap1 = calloc(nlines1, sizeof(*linemap1));
			if (linemap1 == NULL) {
				err = got_error_from_errno("malloc");
				goto done;
			}
		}
		err = blame_changes(blame, linemap1,
		    diffreg_result->result, id, cb, arg);
		if (err) {
			free(linemap1);
			goto done;
		}
		if (linemap1) {
			free(blame->linemap2);
			blame->linemap2 = linemap1;
			blame->nlines2 = nlines1;
		}
	} else if (cb)
		err = cb(arg, blame->nlines, -1, id);
done:
	if (diffreg_result) {
		const struct got_error *free_err;
		free_err = got_diffreg_result_free(diffreg_result);
		if (free_err && err == NULL)
			err = free_err;
	}
	if (commit)
		got_object_commit_close(commit);
	free(blob_id);
	free(pblob_id);
	if (blob)
		got_object_blob_close(blob);
	if (pblob)
		got_object_blob_close(pblob);
	if (f1 && fclose(f1) != 0 && err == NULL)
		err = got_error_from_errno("fclose");
	if (f2 && fclose(f2) != 0 && err == NULL)
		err = got_error_from_errno("fclose");
	return err;
}

static const struct got_error *
blame_close(struct got_blame *blame)
{
	const struct got_error *err = NULL;

	if (blame->f && fclose(blame->f) != 0 && err == NULL)
		err = got_error_from_errno("fclose");
	free(blame->lines);
	free(blame->linemap2);
	free(blame->cfg);
	free(blame);
	return err;
}

static const struct got_error *
blame_open(struct got_blame **blamep, const char *path,
    struct got_object_id *start_commit_id, struct got_repository *repo,
    const struct got_error *(*cb)(void *, int, int, struct got_object_id *),
    void *arg, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_object *obj = NULL;
	struct got_object_id *obj_id = NULL;
	struct got_blob_object *blob = NULL;
	struct got_blame *blame = NULL;
	struct got_object_id *id = NULL;
	int lineno;
	struct got_commit_graph *graph = NULL;

	*blamep = NULL;

	err = got_object_id_by_path(&obj_id, repo, start_commit_id, path);
	if (err)
		goto done;

	err = got_object_open(&obj, repo, obj_id);
	if (err)
		goto done;

	if (obj->type != GOT_OBJ_TYPE_BLOB) {
		err = got_error_path(path, GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = got_object_blob_open(&blob, repo, obj, 8192);
	if (err)
		goto done;

	blame = calloc(1, sizeof(*blame));
	if (blame == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}

	blame->f = got_opentemp();
	if (blame->f == NULL) {
		err = got_error_from_errno("got_opentemp");
		goto done;
	}
	err = got_object_blob_dump_to_file(&blame->filesize, &blame->nlines,
	    &blame->line_offsets, blame->f, blob);
	if (err || blame->nlines == 0)
		goto done;

	err = got_diff_get_config(&blame->cfg, GOT_DIFF_ALGORITHM_PATIENCE,
	    NULL, NULL);
	if (err)
		goto done;

	/* Don't include \n at EOF in the blame line count. */
	if (blame->line_offsets[blame->nlines - 1] == blame->filesize)
		blame->nlines--;

	blame->lines = calloc(blame->nlines, sizeof(*blame->lines));
	if (blame->lines == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}

	blame->nlines2 = blame->nlines;
	blame->linemap2 = calloc(blame->nlines2, sizeof(*blame->linemap2));
	if (blame->linemap2 == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}
	for (lineno = 0; lineno < blame->nlines2; lineno++)
		blame->linemap2[lineno] = lineno;

	err = got_commit_graph_open(&graph, path, 1);
	if (err)
		goto done;

	err = got_commit_graph_iter_start(graph, start_commit_id, repo,
	    cancel_cb, cancel_arg);
	if (err)
		goto done;
	for (;;) {
		struct got_object_id *next_id;
		err = got_commit_graph_iter_next(&next_id, graph, repo,
		    cancel_cb, cancel_arg);
		if (err) {
			if (err->code == GOT_ERR_ITER_COMPLETED) {
				err = NULL;
				break;
			}
			goto done;
		}
		if (next_id) {
			id = next_id;
			err = blame_commit(blame, id, path, repo, cb, arg);
			if (err) {
				if (err->code == GOT_ERR_ITER_COMPLETED)
					err = NULL;
				goto done;
			}
			if (blame->nannotated == blame->nlines)
				break;
		}
	}

	if (id && blame->nannotated < blame->nlines) {
		/* Annotate remaining non-annotated lines with last commit. */
		for (lineno = 0; lineno < blame->nlines; lineno++) {
			err = annotate_line(blame, lineno, id, cb, arg);
			if (err)
				goto done;
		}
	}

done:
	if (graph)
		got_commit_graph_close(graph);
	free(obj_id);
	if (obj)
		got_object_close(obj);
	if (blob)
		got_object_blob_close(blob);
	if (err) {
		if (blame)
			blame_close(blame);
	} else
		*blamep = blame;

	return err;
}

const struct got_error *
got_blame(const char *path, struct got_object_id *commit_id,
    struct got_repository *repo,
    const struct got_error *(*cb)(void *, int, int, struct got_object_id *),
    void *arg, got_cancel_cb cancel_cb, void* cancel_arg)
{
	const struct got_error *err = NULL, *close_err = NULL;
	struct got_blame *blame;
	char *abspath;

	if (asprintf(&abspath, "%s%s", path[0] == '/' ? "" : "/", path) == -1)
		return got_error_from_errno2("asprintf", path);

	err = blame_open(&blame, abspath, commit_id, repo, cb, arg,
	    cancel_cb, cancel_arg);
	free(abspath);
	if (blame)
		close_err = blame_close(blame);
	return err ? err : close_err;
}
