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
#include <sys/stat.h>

#include <sha1.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <util.h>
#include <zlib.h>

#include "got_error.h"
#include "got_object.h"
#include "got_blame.h"
#include "got_opentemp.h"

#include "got_lib_inflate.h"
#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_diff.h"
#include "got_lib_diffoffset.h"
#include "got_commit_graph.h"

struct got_blame_line {
	int annotated;
	struct got_object_id id;
};

struct got_blame_diff_offsets {
	struct got_diffoffset_chunks *chunks;
	struct got_object_id *commit_id;
	SLIST_ENTRY(got_blame_diff_offsets) entry;
};

SLIST_HEAD(got_blame_diff_offsets_list, got_blame_diff_offsets);

struct got_blame {
	FILE *f;
	int nlines;
	int nannotated;
	struct got_blame_line *lines; /* one per line */
	int ncommits;
	struct got_blame_diff_offsets_list diff_offsets_list;
};

static void
free_diff_offsets(struct got_blame_diff_offsets *diff_offsets)
{
	if (diff_offsets->chunks)
		got_diffoffset_free(diff_offsets->chunks);
	free(diff_offsets->commit_id);
	free(diff_offsets);
}

static const struct got_error *
alloc_diff_offsets(struct got_blame_diff_offsets **diff_offsets,
    struct got_object_id *commit_id)
{
	const struct got_error *err = NULL;

	*diff_offsets = calloc(1, sizeof(**diff_offsets));
	if (*diff_offsets == NULL)
		return got_error_prefix_errno("calloc");

	(*diff_offsets)->commit_id = got_object_id_dup(commit_id);
	if ((*diff_offsets)->commit_id == NULL) {
		err = got_error_prefix_errno("got_object_id_dup");
		free_diff_offsets(*diff_offsets);
		*diff_offsets = NULL;
		return err;
	}

	err = got_diffoffset_alloc(&(*diff_offsets)->chunks);
	if (err) {
		free_diff_offsets(*diff_offsets);
		return err;
	}

	return NULL;
}

static const struct got_error *
annotate_line(struct got_blame *blame, int lineno, struct got_object_id *id,
    const struct got_error *(*cb)(void *, int, int, struct got_object_id *),
    void *arg)
{
	const struct got_error *err = NULL;
	struct got_blame_line *line;

	if (lineno < 1 || lineno > blame->nlines)
		return NULL;
	
	line = &blame->lines[lineno - 1];
	if (line->annotated)
		return NULL;

	memcpy(&line->id, id, sizeof(line->id));
	line->annotated = 1;
	blame->nannotated++;
	if (cb)
		err = cb(arg, blame->nlines, lineno, id);
	return err;
}

static int
get_blamed_line(struct got_blame_diff_offsets_list *diff_offsets_list,
    int lineno)
{
	struct got_blame_diff_offsets *diff_offsets;

	SLIST_FOREACH(diff_offsets, diff_offsets_list, entry)
		lineno = got_diffoffset_get(diff_offsets->chunks, lineno);

	return lineno;
}

static const struct got_error *
blame_changes(struct got_blame *blame, struct got_diff_changes *changes,
    struct got_object_id *commit_id,
    const struct got_error *(*cb)(void *, int, int, struct got_object_id *),
    void *arg)
{
	const struct got_error *err = NULL;
	struct got_diff_change *change;
	struct got_blame_diff_offsets *diff_offsets;

	SIMPLEQ_FOREACH(change, &changes->entries, entry) {
		int c = change->cv.c;
		int d = change->cv.d;
		int new_lineno = c;
		int new_length = (c < d ? d - c + 1 : (c == d ? 1 : 0));
		int ln;

		for (ln = new_lineno; ln < new_lineno + new_length; ln++) {
			err = annotate_line(blame,
			    get_blamed_line(&blame->diff_offsets_list, ln),
			    commit_id, cb, arg);
			if (err)
				return err;
			if (blame->nlines == blame->nannotated)
				return NULL;
		}
	}

	err = alloc_diff_offsets(&diff_offsets, commit_id);
	if (err)
		return err;
	SIMPLEQ_FOREACH(change, &changes->entries, entry) {
		int a = change->cv.a;
		int b = change->cv.b;
		int c = change->cv.c;
		int d = change->cv.d;
		int old_lineno = a;
		int old_length = (a < b ? b - a + 1 : (a == b ? 1 : 0));
		int new_lineno = c;
		int new_length = (c < d ? d - c + 1 : (c == d ? 1 : 0));

		err = got_diffoffset_add(diff_offsets->chunks,
		    old_lineno, old_length, new_lineno, new_length);
		if (err) {
			free_diff_offsets(diff_offsets);
			return err;
		}
	}
	SLIST_INSERT_HEAD(&blame->diff_offsets_list, diff_offsets, entry);

	return NULL;
}

static const struct got_error *
blame_commit(struct got_blame *blame, struct got_object_id *id,
    struct got_object_id *pid, const char *path, struct got_repository *repo,
    const struct got_error *(*cb)(void *, int, int, struct got_object_id *),
    void *arg)
{
	const struct got_error *err = NULL;
	struct got_object *obj = NULL, *pobj = NULL;
	struct got_object_id *obj_id = NULL, *pobj_id = NULL;
	struct got_blob_object *blob = NULL, *pblob = NULL;
	struct got_diff_changes *changes = NULL;

	err = got_object_id_by_path(&obj_id, repo, id, path);
	if (err)
		goto done;

	err = got_object_open(&obj, repo, obj_id);
	if (err)
		goto done;

	if (obj->type != GOT_OBJ_TYPE_BLOB) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = got_object_id_by_path(&pobj_id, repo, pid, path);
	if (err) {
		if (err->code == GOT_ERR_NO_TREE_ENTRY) {
			/* Blob's history began in previous commit. */
			err = got_error(GOT_ERR_ITER_COMPLETED);
		}
		goto done;
	}

	/* If IDs match then don't bother with diffing. */
	if (got_object_id_cmp(obj_id, pobj_id) == 0) {
		if (cb)
			err = cb(arg, blame->nlines, -1, id);
		goto done;
	}

	err = got_object_open(&pobj, repo, pobj_id);
	if (err)
		goto done;

	if (pobj->type != GOT_OBJ_TYPE_BLOB) {
		/*
		 * Encountered a non-blob at the path (probably a tree).
		 * Blob's history began in previous commit.
		 */
		err = got_error(GOT_ERR_ITER_COMPLETED);
		goto done;
	}

	err = got_object_blob_open(&blob, repo, obj, 8192);
	if (err)
		goto done;

	err = got_object_blob_open(&pblob, repo, pobj, 8192);
	if (err)
		goto done;

	err = got_diff_blob_lines_changed(&changes, pblob, blob);
	if (err)
		goto done;

	if (changes) {
		err = blame_changes(blame, changes, id, cb, arg);
		got_diff_free_changes(changes);
	} else if (cb)
		err = cb(arg, blame->nlines, -1, id);
done:
	free(obj_id);
	free(pobj_id);
	if (obj)
		got_object_close(obj);
	if (pobj)
		got_object_close(pobj);
	if (blob)
		got_object_blob_close(blob);
	if (pblob)
		got_object_blob_close(pblob);
	return err;
}

static const struct got_error *
blame_close(struct got_blame *blame)
{
	const struct got_error *err = NULL;
	struct got_blame_diff_offsets *diff_offsets;

	if (blame->f && fclose(blame->f) != 0)
		err = got_error_prefix_errno("fclose");
	free(blame->lines);
	while (!SLIST_EMPTY(&blame->diff_offsets_list)) {
		diff_offsets = SLIST_FIRST(&blame->diff_offsets_list);
		SLIST_REMOVE_HEAD(&blame->diff_offsets_list, entry);
		free_diff_offsets(diff_offsets);
	}
	free(blame);
	return err;
}

static const struct got_error *
blame_open(struct got_blame **blamep, const char *path,
    struct got_object_id *start_commit_id, struct got_repository *repo,
    const struct got_error *(*cb)(void *, int, int, struct got_object_id *),
    void *arg)
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
		return err;

	err = got_object_open(&obj, repo, obj_id);
	if (err)
		goto done;

	if (obj->type != GOT_OBJ_TYPE_BLOB) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = got_object_blob_open(&blob, repo, obj, 8192);
	if (err)
		goto done;

	blame = calloc(1, sizeof(*blame));
	if (blame == NULL)
		return got_error_prefix_errno("calloc");

	blame->f = got_opentemp();
	if (blame->f == NULL) {
		err = got_error_prefix_errno("got_opentemp");
		goto done;
	}
	err = got_object_blob_dump_to_file(NULL, &blame->nlines, blame->f,
	    blob);
	if (err)
		goto done;

	blame->lines = calloc(blame->nlines, sizeof(*blame->lines));
	if (blame->lines == NULL) {
		err = got_error_prefix_errno("calloc");
		goto done;
	}

	err = got_commit_graph_open(&graph, start_commit_id, path, 0, repo);
	if (err)
		return err;
	err = got_commit_graph_iter_start(graph, start_commit_id, repo);
	if (err)
		goto done;

	id = NULL;
	for (;;) {
		struct got_object_id *next_id;

		err = got_commit_graph_iter_next(&next_id, graph);
		if (err) {
			if (err->code == GOT_ERR_ITER_COMPLETED) {
				err = NULL;
				break;
			}
			if (err->code != GOT_ERR_ITER_NEED_MORE)
				break;
			err = got_commit_graph_fetch_commits(graph, 1, repo);
			if (err)
				break;
			else
				continue;
		}
		if (next_id == NULL)
			break;
		if (id) {
			err = blame_commit(blame, id, next_id, path, repo,
			    cb, arg);
			if (err) {
				if (err->code == GOT_ERR_ITER_COMPLETED)
					err = NULL;
				break;
			}
			if (blame->nannotated == blame->nlines)
				break;
		}
		id = next_id;
	}

	if (id && blame->nannotated < blame->nlines) {
		/* Annotate remaining non-annotated lines with last commit. */
		for (lineno = 1; lineno <= blame->nlines; lineno++) {
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

static const struct got_error *
blame_line(struct got_object_id **id, struct got_blame *blame, int lineno)
{
	if (lineno < 1 || lineno > blame->nlines)
		return got_error(GOT_ERR_RANGE);
	*id = &blame->lines[lineno - 1].id;
	return NULL;
}

static char *
parse_next_line(FILE *f, size_t *len)
{
	char *line;
	size_t linelen;
	size_t lineno;
	const char delim[3] = { '\0', '\0', '\0'};

	line = fparseln(f, &linelen, &lineno, delim, 0);
	if (len)
		*len = linelen;
	return line;
}

const struct got_error *
got_blame(const char *path, struct got_object_id *start_commit_id,
    struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err = NULL, *close_err = NULL;
	struct got_blame *blame;
	int lineno;
	char *abspath;

	if (asprintf(&abspath, "%s%s", path[0] == '/' ? "" : "/", path) == -1)
		return got_error_prefix_errno2("asprintf", path);

	err = blame_open(&blame, abspath, start_commit_id, repo, NULL, NULL);
	if (err) {
		free(abspath);
		return err;
	}

	for (lineno = 1; lineno <= blame->nlines; lineno++) {
		struct got_object_id *id;
		char *line, *id_str;

		line = parse_next_line(blame->f, NULL);
		if (line == NULL)
			break;

		err = blame_line(&id, blame, lineno);
		if (err) {
			free(line);
			break;
		}

		err = got_object_id_str(&id_str, id);
		/* Do not free id; It points into blame->lines. */
		if (err) {
			free(line);
			break;
		}

		fprintf(outfile, "%.8s %s\n", id_str, line);
		free(line);
		free(id_str);
	}

	close_err = blame_close(blame);
	free(abspath);
	return err ? err : close_err;
}

const struct got_error *
got_blame_incremental(const char *path, struct got_object_id *commit_id,
    struct got_repository *repo,
    const struct got_error *(*cb)(void *, int, int, struct got_object_id *),
    void *arg)
{
	const struct got_error *err = NULL, *close_err = NULL;
	struct got_blame *blame;
	char *abspath;

	if (asprintf(&abspath, "%s%s", path[0] == '/' ? "" : "/", path) == -1)
		return got_error_prefix_errno2("asprintf", path);

	err = blame_open(&blame, abspath, commit_id, repo, cb, arg);
	free(abspath);
	if (blame)
		close_err = blame_close(blame);
	return err ? err : close_err;
}
