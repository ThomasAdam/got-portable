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
#include <sys/stat.h>

#include <sha1.h>
#include <string.h>
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

struct got_blame_line {
	int annotated;
	struct got_object_id id;
};

struct got_blame {
	FILE *f;
	size_t filesize;
	int nlines;
	int nannotated;
	struct got_blame_line *lines; /* one per line */
	off_t *line_offsets;		/* one per line */
	int ncommits;
};

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

static const struct got_error *
blame_changes(struct got_blame *blame, struct got_diff_changes *changes,
    struct got_object_id *commit_id,
    const struct got_error *(*cb)(void *, int, int, struct got_object_id *),
    void *arg)
{
	const struct got_error *err = NULL;
	struct got_diff_change *change;

	SIMPLEQ_FOREACH(change, &changes->entries, entry) {
		int c = change->cv.c;
		int d = change->cv.d;
		int new_lineno = (c < d ? c : d);
		int new_length = (c < d ? d - c + 1 : (c == d ? 1 : 0));
		int ln;

		for (ln = new_lineno; ln < new_lineno + new_length; ln++) {
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
blame_commit(struct got_blame *blame, struct got_object_id *parent_id,
    struct got_object_id *id, const char *path, struct got_repository *repo,
    const struct got_error *(*cb)(void *, int, int, struct got_object_id *),
    void *arg)
{
	const struct got_error *err = NULL;
	struct got_object *obj = NULL;
	struct got_object_id *obj_id = NULL;
	struct got_commit_object *commit = NULL;
	struct got_blob_object *blob = NULL;
	struct got_diff_changes *changes = NULL;

	err = got_object_open_as_commit(&commit, repo, parent_id);
	if (err)
		return err;

	err = got_object_id_by_path(&obj_id, repo, parent_id, path);
	if (err) {
		if (err->code == GOT_ERR_NO_TREE_ENTRY)
			err = NULL;
		goto done;
	}

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

	if (fseek(blame->f, 0L, SEEK_SET) == -1) {
		err = got_ferror(blame->f, GOT_ERR_IO);
		goto done;
	}

	err = got_diff_blob_file_lines_changed(&changes, blob, blame->f,
	    blame->filesize);
	if (err)
		goto done;

	if (changes) {
		err = blame_changes(blame, changes, id, cb, arg);
		got_diff_free_changes(changes);
	} else if (cb)
		err = cb(arg, blame->nlines, -1, id);
done:
	if (commit)
		got_object_commit_close(commit);
	free(obj_id);
	if (obj)
		got_object_close(obj);
	if (blob)
		got_object_blob_close(blob);
	return err;
}

static const struct got_error *
blame_close(struct got_blame *blame)
{
	const struct got_error *err = NULL;

	if (blame->f && fclose(blame->f) != 0)
		err = got_error_from_errno("fclose");
	free(blame->lines);
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
	struct got_object_id *id = NULL, *pid = NULL;
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
		return got_error_from_errno("calloc");

	blame->f = got_opentemp();
	if (blame->f == NULL) {
		err = got_error_from_errno("got_opentemp");
		goto done;
	}
	err = got_object_blob_dump_to_file(&blame->filesize, &blame->nlines,
	   &blame->line_offsets, blame->f, blob);
	if (err || blame->nlines == 0)
		goto done;

	/* Don't include \n at EOF in the blame line count. */
	if (blame->line_offsets[blame->nlines - 1] == blame->filesize)
		blame->nlines--;

	blame->lines = calloc(blame->nlines, sizeof(*blame->lines));
	if (blame->lines == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}

	err = got_commit_graph_open(&graph, path, 1);
	if (err)
		return err;
	err = got_commit_graph_iter_start(graph, start_commit_id, repo,
	    cancel_cb, cancel_arg);
	if (err)
		goto done;
	id = start_commit_id;
	for (;;) {
		err = got_commit_graph_iter_next(&pid, graph, repo,
		    cancel_cb, cancel_arg);
		if (err) {
			if (err->code == GOT_ERR_ITER_COMPLETED)
				err = NULL;
			break;
		}
		if (pid) {
			err = blame_commit(blame, pid, id, path, repo, cb, arg);
			if (err) {
				if (err->code == GOT_ERR_ITER_COMPLETED)
					err = NULL;
				break;
			}
			if (blame->nannotated == blame->nlines)
				break;
		}
		id = pid;
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
