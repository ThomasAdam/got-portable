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

#include "got_lib_zbuf.h"
#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_diff.h"

struct got_blame_line {
	int annotated;
	struct got_object_id id;
};

struct got_blame {
	FILE *f;
	size_t nlines;
	struct got_blame_line *lines; /* one per line */
};

static const struct got_error *
dump_blob_and_count_lines(size_t *nlines, FILE *outfile,
    struct got_blob_object *blob)
{
	const struct got_error *err = NULL;
	size_t len, hdrlen;
	const uint8_t *buf;
	int i;

	hdrlen = got_object_blob_get_hdrlen(blob);
	*nlines = 0;
	do {
		err = got_object_blob_read_block(&len, blob);
		if (err)
			return err;
		if (len == 0)
			break;
		buf = got_object_blob_get_read_buf(blob);
		for (i = 0; i < len; i++) {
			if (buf[i] == '\n')
				(*nlines)++;
		}
		/* Skip blob object header first time around. */
		fwrite(buf + hdrlen, len - hdrlen, 1, outfile);
		hdrlen = 0;
	} while (len != 0);


	fflush(outfile);
	rewind(outfile);

	return NULL;
}

static void
annotate_line(struct got_blame *blame, int lineno, struct got_object_id *id)
{
	struct got_blame_line *line;

	if (lineno < 1 || lineno > blame->nlines)
		return;
	
	line = &blame->lines[lineno - 1];
	if (line->annotated)
		return;

	memcpy(&line->id, id, sizeof(line->id));
	line->annotated = 1;
}

static const struct got_error *
blame_commit(struct got_blame *blame, struct got_object_id *id,
    struct got_object_id *pid, const char *path, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object *obj = NULL, *pobj = NULL;
	struct got_blob_object *blob = NULL, *pblob = NULL;
	struct got_diff_changes *changes = NULL;

	err = got_object_open_by_path(&obj, repo, id, path);
	if (err)
		goto done;
	if (got_object_get_type(obj) != GOT_OBJ_TYPE_BLOB) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = got_object_open_by_path(&pobj, repo, pid, path);
	if (err) {
		if (err->code == GOT_ERR_NO_OBJ) {
			/* Blob's history began in previous commit. */
			err = got_error(GOT_ERR_ITER_COMPLETED);
		}
		goto done;
	}
	if (got_object_get_type(pobj) != GOT_OBJ_TYPE_BLOB) {
		/*
		 * Encountered a non-blob at the path (probably a tree).
		 * Blob's history began in previous commit.
		 */
		err = got_error(GOT_ERR_ITER_COMPLETED);
		goto done;
	}

	/* If blob hashes match then don't bother with diffing. */
	if (got_object_id_cmp(&obj->id, &pobj->id) == 0)
		goto done;

	err = got_object_blob_open(&blob, repo, obj, 8192);
	if (err)
		goto done;

	err = got_object_blob_open(&pblob, repo, pobj, 8192);
	if (err)
		goto done;

	err = got_diff_blob_lines_changed(&changes, blob, pblob);
	if (err)
		goto done;

	if (changes) {
		struct got_diff_change *change;
		SIMPLEQ_FOREACH(change, &changes->entries, entry) {
			int a = change->cv.a;
			int b = change->cv.b;
			int lineno;
			for (lineno = a; lineno <= b; lineno++)
				annotate_line(blame, lineno, id);
		}
	}
done:
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

static void
blame_close(struct got_blame *blame)
{
	if (blame->f)
		fclose(blame->f);
	free(blame->lines);
	free(blame);
}

static const struct got_error *
blame_open(struct got_blame **blamep, const char *path,
    struct got_object_id *start_commit_id, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object *obj = NULL;
	struct got_blob_object *blob = NULL;
	struct got_blame *blame = NULL;
	struct got_commit_object *commit = NULL;
	struct got_object_id *id = NULL;
	int lineno;

	*blamep = NULL;

	err = got_object_open_by_path(&obj, repo, start_commit_id, path);
	if (err)
		return err;
	if (got_object_get_type(obj) != GOT_OBJ_TYPE_BLOB) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = got_object_blob_open(&blob, repo, obj, 8192);
	if (err)
		goto done;

	blame = calloc(1, sizeof(*blame));
	if (blame == NULL)
		return got_error_from_errno();

	blame->f = got_opentemp();
	if (blame->f == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	err = dump_blob_and_count_lines(&blame->nlines, blame->f, blob);
	if (err)
		goto done;

	blame->lines = calloc(blame->nlines, sizeof(*blame->lines));
	if (blame->lines == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	/* Loop over first-parent history and try to blame commits. */
	err = got_object_open_as_commit(&commit, repo, start_commit_id);
	if (err)
		goto done;
	id = got_object_id_dup(start_commit_id);
	if (id == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	while (1) {
		struct got_object_qid *pid;

		pid = SIMPLEQ_FIRST(&commit->parent_ids);
		if (pid == NULL)
			break;

		err = blame_commit(blame, id, pid->id, path, repo);
		if (err) {
			if (err->code == GOT_ERR_ITER_COMPLETED)
				err = NULL;
			break;
		}

		free(id);
		id = got_object_id_dup(pid->id);
		if (id == NULL) {
			err = got_error_from_errno();
			goto done;
		}
		got_object_commit_close(commit);
		err = got_object_open_as_commit(&commit, repo, id);
		if (err)
			break;
	}

	/* Annotate remaining non-annotated lines with last commit. */
	for (lineno = 1; lineno < blame->nlines; lineno++)
		annotate_line(blame, lineno, id);

done:
	free(id);
	if (obj)
		got_object_close(obj);
	if (blob)
		got_object_blob_close(blob);
	if (commit)
		got_object_commit_close(commit);
	if (err)
		blame_close(blame);
	else
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
	const struct got_error *err = NULL;
	struct got_blame *blame;
	int lineno;
	char *abspath;

	if (asprintf(&abspath, "%s%s", path[0] == '/' ? "" : "/", path) == -1)
		return got_error_from_errno();

	err = blame_open(&blame, abspath, start_commit_id, repo);
	if (err) {
		free(abspath);
		return err;
	}

	for (lineno = 1; lineno < blame->nlines; lineno++) {
		struct got_object_id *id;
		char *line, *id_str;
		
		line = parse_next_line(blame->f, NULL);
		if (line == NULL)
			break;

		err = blame_line(&id, blame, lineno);
		if (err)
			break;

		err = got_object_id_str(&id_str, id);
		if (err) {
			free(line);
			break;
		}

		fprintf(outfile, "%.8s %s\n", id_str, line);
		free(line);
		free(id_str);
	}

	blame_close(blame);
	free(abspath);
	return err;
}
