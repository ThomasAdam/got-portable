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

#include <errno.h>
#include <sha1.h>
#include <sha2.h>
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
#include "got_commit_graph.h"
#include "got_opentemp.h"
#include "got_diff.h"
#include "got_blame.h"

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
	struct diff_config *cfg;
	int nlines;	/* number of lines in file being blamed */
	int nannotated;	/* number of lines already annotated */
	struct got_blame_line *lines; /* one per line */
	int ncommits;

	/*
	 * These change with every traversed commit. After diffing
	 * commits N:N-1, in preparation for diffing commits N-1:N-2,
	 * data for commit N is retained and flipped into data for N-1.
	 *
	 */
	FILE *f1; /* older version from commit N-1. */
	FILE *f2; /* newer version from commit N. */
	int fd;
	unsigned char *map1;
	unsigned char *map2;
	off_t size1;
	off_t size2;
	int nlines1;
	int nlines2;
	off_t *line_offsets1;
	off_t *line_offsets2;

	/*
	 * Map line numbers of an older version of the file to valid line
	 * numbers in the version of the file being blamed. This map is
	 * updated with each commit we traverse throughout the file's history.
	 * Lines mapped to -1 do not correspond to any line in the version
	 * being blamed.
	 */
	int *linemap1;
	int *linemap2;

	struct diff_data *data1;
	struct diff_data *data2;
};

static const struct got_error *
annotate_line(struct got_blame *blame, int lineno,
    struct got_commit_object *commit, struct got_object_id *id,
    got_blame_cb cb, void *arg)
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
		err = cb(arg, blame->nlines, lineno + 1, commit, id);
	return err;
}

static const struct got_error *
blame_changes(struct got_blame *blame, struct diff_result *diff_result,
    struct got_commit_object *commit, struct got_object_id *commit_id,
    got_blame_cb cb, void *arg)
{
	const struct got_error *err = NULL;
	int i;
	int idx1 = 0, idx2 = 0;

	for (i = 0; i < diff_result->chunks.len &&
	    blame->nannotated < blame->nlines; i++) {
		struct diff_chunk *c = diff_chunk_get(diff_result, i);
		unsigned int left_count, right_count;
		int j;

		/*
		 * We do not need to worry about idx1/idx2 growing out
		 * of bounds because the diff implementation ensures
		 * that chunk ranges never exceed the number of lines
		 * in the left/right input files.
		 */
		left_count = diff_chunk_get_left_count(c);
		right_count = diff_chunk_get_right_count(c);

		if (left_count == right_count) {
			for (j = 0; j < left_count; j++) {
				blame->linemap1[idx1++] =
				    blame->linemap2[idx2++];
			}
			continue;
		}

		if (right_count == 0) {
			for (j = 0; j < left_count; j++) {
				blame->linemap1[idx1++] = -1;
			}
			continue;
		}

		for (j = 0; j < right_count; j++) {
			int ln = blame->linemap2[idx2++];
			err = annotate_line(blame, ln, commit, commit_id,
			    cb, arg);
			if (err)
				return err;
			if (blame->nlines == blame->nannotated)
				break;
		}
	}

	return NULL;
}

static const struct got_error *
blame_prepare_file(FILE *f, unsigned char **p, off_t *size,
    int *nlines, off_t **line_offsets, struct diff_data *diff_data,
    const struct diff_config *cfg, struct got_blob_object *blob)
{
	const struct got_error *err = NULL;
	int diff_flags = 0, rc;

	err = got_object_blob_dump_to_file(size, nlines, line_offsets,
	    f, blob);
	if (err)
		return err;

#ifndef GOT_DIFF_NO_MMAP
	*p = mmap(NULL, *size, PROT_READ, MAP_PRIVATE, fileno(f), 0);
	if (*p == MAP_FAILED)
#endif
		*p = NULL; /* fall back on file I/O */

	/* Allow blaming lines in binary files even though it's useless. */
	diff_flags |= DIFF_FLAG_FORCE_TEXT_DATA;

	rc = diff_atomize_file(diff_data, cfg, f, *p, *size, diff_flags);
	if (rc)
		return got_error_set_errno(rc, "diff_atomize_file");

	return NULL;
}

static const struct got_error *
blame_commit(struct got_blame *blame, struct got_object_id *id,
    const char *path, struct got_repository *repo,
    got_blame_cb cb, void *arg)
{
	const struct got_error *err = NULL;
	struct got_commit_object *commit = NULL, *pcommit = NULL;
	struct got_object_qid *pid = NULL;
	struct got_object_id *pblob_id = NULL;
	struct got_blob_object *pblob = NULL;
	struct diff_result *diff_result = NULL;

	err = got_object_open_as_commit(&commit, repo, id);
	if (err)
		return err;

	pid = STAILQ_FIRST(got_object_commit_get_parent_ids(commit));
	if (pid == NULL) {
		got_object_commit_close(commit);
		return NULL;
	}

	err = got_object_open_as_commit(&pcommit, repo, &pid->id);
	if (err)
		goto done;

	err = got_object_id_by_path(&pblob_id, repo, pcommit, path);
	if (err) {
		if (err->code == GOT_ERR_NO_TREE_ENTRY)
			err = NULL;
		goto done;
	}

	err = got_object_open_as_blob(&pblob, repo, pblob_id, 8192, blame->fd);
	if (err)
		goto done;

	err = blame_prepare_file(blame->f1, &blame->map1, &blame->size1,
	    &blame->nlines1, &blame->line_offsets1, blame->data1,
	    blame->cfg, pblob);
	if (err)
		goto done;

	diff_result = diff_main(blame->cfg, blame->data1, blame->data2);
	if (diff_result == NULL) {
		err = got_error_set_errno(ENOMEM, "malloc");
		goto done;
	}
	if (diff_result->rc != DIFF_RC_OK) {
		err = got_error_set_errno(diff_result->rc, "diff");
		goto done;
	}
	if (diff_result->chunks.len > 0) {
		if (blame->nlines1 > 0) {
			blame->linemap1 = calloc(blame->nlines1,
			    sizeof(*blame->linemap1));
			if (blame->linemap1 == NULL) {
				err = got_error_from_errno("malloc");
				goto done;
			}
		}
		err = blame_changes(blame, diff_result, commit, id, cb, arg);
		if (err)
			goto done;
	} else if (cb)
		err = cb(arg, blame->nlines, -1, commit, id);
done:
	if (diff_result)
		diff_result_free(diff_result);
	if (commit)
		got_object_commit_close(commit);
	if (pcommit)
		got_object_commit_close(pcommit);
	free(pblob_id);
	if (pblob)
		got_object_blob_close(pblob);
	return err;
}

static const struct got_error *
blame_close(struct got_blame *blame)
{
	const struct got_error *err = NULL;

	diff_data_free(blame->data1);
	free(blame->data1);
	diff_data_free(blame->data2);
	free(blame->data2);
	if (blame->map1) {
		if (munmap(blame->map1, blame->size1) == -1 && err == NULL)
			err = got_error_from_errno("munmap");
	}
	if (blame->map2) {
		if (munmap(blame->map2, blame->size2) == -1 && err == NULL)
			err = got_error_from_errno("munmap");
	}
	free(blame->lines);
	free(blame->line_offsets1);
	free(blame->line_offsets2);
	free(blame->linemap1);
	free(blame->linemap2);
	free(blame->cfg);
	free(blame);
	return err;
}

static int
atomize_file(struct diff_data *d, FILE *f, off_t filesize, int nlines,
    off_t *line_offsets)
{
	int i, rc = DIFF_RC_OK;
	int embedded_nul = 0;

	ARRAYLIST_INIT(d->atoms, nlines);

	for (i = 0; i < nlines; i++) {
		struct diff_atom *atom;
		off_t len, pos = line_offsets[i];
		unsigned int hash = 0;
		int j;

		ARRAYLIST_ADD(atom, d->atoms);
		if (atom == NULL) {
			rc = errno;
			break;
		}

		if (i < nlines - 1)
			len = line_offsets[i + 1] - pos;
		else
			len = filesize - pos;

		if (fseeko(f, pos, SEEK_SET) == -1) {
			rc = errno;
			break;
		}
		for (j = 0; j < len; j++) {
			int c = fgetc(f);
			if (c == EOF) {
				if (feof(f))
					rc = EIO; /* unexpected EOF */
				else
					rc = errno;
				goto done;
			}

			hash = diff_atom_hash_update(hash, (unsigned char)c);

			if (c == '\0')
				embedded_nul = 1;

		}
		*atom = (struct diff_atom){
			.root = d,
			.pos = pos,
			.at = NULL,	/* atom data is not memory-mapped */
			.len = len,
			.hash = hash,
		};
	}

	/* File are considered binary if they contain embedded '\0' bytes. */
	if (embedded_nul)
		d->atomizer_flags |= DIFF_ATOMIZER_FOUND_BINARY_DATA;
done:
	if (rc)
		ARRAYLIST_FREE(d->atoms);

	return rc;
}

static int
atomize_file_mmap(struct diff_data *d, unsigned char *p,
    off_t filesize, int nlines, off_t *line_offsets)
{
	int i, rc = DIFF_RC_OK;
	int embedded_nul = 0;

	ARRAYLIST_INIT(d->atoms, nlines);

	for (i = 0; i < nlines; i++) {
		struct diff_atom *atom;
		off_t len, pos = line_offsets[i];
		unsigned int hash = 0;
		int j;

		ARRAYLIST_ADD(atom, d->atoms);
		if (atom == NULL) {
			rc = errno;
			break;
		}

		if (i < nlines - 1)
			len = line_offsets[i + 1] - pos;
		else
			len = filesize - pos;

		for (j = 0; j < len; j++)
			hash = diff_atom_hash_update(hash, p[pos + j]);

		if (!embedded_nul && memchr(&p[pos], '\0', len) != NULL)
			embedded_nul = 1;

		*atom = (struct diff_atom){
			.root = d,
			.pos = pos,
			.at = &p[pos],
			.len = len,
			.hash = hash,
		};
	}

	/* File are considered binary if they contain embedded '\0' bytes. */
	if (embedded_nul)
		d->atomizer_flags |= DIFF_ATOMIZER_FOUND_BINARY_DATA;

	if (rc)
		ARRAYLIST_FREE(d->atoms);

	return rc;
}

/* Implements diff_atomize_func_t */
static int
blame_atomize_file(void *arg, struct diff_data *d)
{
	struct got_blame *blame = arg;

	if (d->f == blame->f1) {
		if (blame->map1)
			return atomize_file_mmap(d, blame->map1,
			    blame->size1, blame->nlines1,
			    blame->line_offsets1);
		else
			return atomize_file(d, blame->f1, blame->size1,
			    blame->nlines1, blame->line_offsets1);
	} else if (d->f == blame->f2) {
		if (d->atoms.len > 0) {
			/* Reuse data from previous commit. */
			return DIFF_RC_OK;
		}
		if (blame->map2)
			return atomize_file_mmap(d, blame->map2,
			    blame->size2, blame->nlines2,
			    blame->line_offsets2);
		else
			return atomize_file(d, blame->f2, blame->size2,
			    blame->nlines2, blame->line_offsets2);
	}

	return DIFF_RC_OK;
}

static const struct got_error *
flip_files(struct got_blame *blame)
{
	const struct got_error *err = NULL;
	struct diff_data *d;
	FILE *tmp;

	free(blame->line_offsets2);
	blame->line_offsets2 = blame->line_offsets1;
	blame->line_offsets1 = NULL;

	free(blame->linemap2);
	blame->linemap2 = blame->linemap1;
	blame->linemap1 = NULL;

	if (blame->map2) {
		if (munmap(blame->map2, blame->size2) == -1)
			return got_error_from_errno("munmap");
		blame->map2 = blame->map1;
		blame->map1 = NULL;
	}
	blame->size2 = blame->size1;

	err = got_opentemp_truncate(blame->f2);
	if (err)
		return err;
	tmp = blame->f2;
	blame->f2 = blame->f1;
	blame->f1 = tmp;
	blame->size1 = 0;

	blame->nlines2 = blame->nlines1;
	blame->nlines1 = 0;

	diff_data_free(blame->data2); /* does not free pointer itself */
	memset(blame->data2, 0, sizeof(*blame->data2));
	d = blame->data2;
	blame->data2 = blame->data1;
	blame->data1 = d;

	return NULL;
}

static const struct got_error *
blame_open(struct got_blame **blamep, const char *path,
    struct got_object_id *start_commit_id, struct got_repository *repo,
    enum got_diff_algorithm diff_algo, got_blame_cb cb, void *arg,
    got_cancel_cb cancel_cb, void *cancel_arg,
    int fd1, int fd2, FILE *f1, FILE *f2)
{
	const struct got_error *err = NULL;
	struct got_commit_object *start_commit = NULL, *last_commit = NULL;
	struct got_object_id *obj_id = NULL;
	struct got_blob_object *blob = NULL;
	struct got_blame *blame = NULL;
	struct got_object_id id;
	int lineno, have_id = 0;
	struct got_commit_graph *graph = NULL;

	*blamep = NULL;

	err = got_object_open_as_commit(&start_commit, repo, start_commit_id);
	if (err)
		goto done;

	err = got_object_id_by_path(&obj_id, repo, start_commit, path);
	if (err)
		goto done;

	err = got_object_open_as_blob(&blob, repo, obj_id, 8192, fd1);
	if (err)
		goto done;

	blame = calloc(1, sizeof(*blame));
	if (blame == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}

	blame->data1 = calloc(1, sizeof(*blame->data1));
	if (blame->data1 == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}
	blame->data2 = calloc(1, sizeof(*blame->data2));
	if (blame->data2 == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}

	blame->f1 = f1;
	blame->f2 = f2;
	blame->fd = fd2;

	err = got_diff_get_config(&blame->cfg, diff_algo, blame_atomize_file,
	    blame);
	if (err)
		goto done;

	err = blame_prepare_file(blame->f2, &blame->map2, &blame->size2,
	    &blame->nlines2, &blame->line_offsets2, blame->data2,
	    blame->cfg, blob);
	blame->nlines = blame->nlines2;
	if (err || blame->nlines == 0)
		goto done;

	got_object_blob_close(blob);
	blob = NULL;

	/* Don't include \n at EOF in the blame line count. */
	if (blame->line_offsets2[blame->nlines - 1] == blame->size2)
		blame->nlines--;

	blame->lines = calloc(blame->nlines, sizeof(*blame->lines));
	if (blame->lines == NULL) {
		err = got_error_from_errno("calloc");
		goto done;
	}

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

	err = got_commit_graph_bfsort(graph, start_commit_id, repo,
	    cancel_cb, cancel_arg);
	if (err)
		goto done;
	for (;;) {
		err = got_commit_graph_iter_next(&id, graph, repo,
		    cancel_cb, cancel_arg);
		if (err) {
			if (err->code == GOT_ERR_ITER_COMPLETED) {
				err = NULL;
				break;
			}
			goto done;
		}
		have_id = 1;

		err = blame_commit(blame, &id, path, repo, cb, arg);
		if (err) {
			if (err->code == GOT_ERR_ITER_COMPLETED)
				err = NULL;
			goto done;
		}
		if (blame->nannotated == blame->nlines)
			break;

		err = flip_files(blame);
		if (err)
			goto done;
	}

	if (have_id && blame->nannotated < blame->nlines) {
		/* Annotate remaining non-annotated lines with last commit. */
		err = got_object_open_as_commit(&last_commit, repo, &id);
		if (err)
			goto done;
		for (lineno = 0; lineno < blame->nlines; lineno++) {
			err = annotate_line(blame, lineno, last_commit, &id,
			    cb, arg);
			if (err)
				goto done;
		}
	}

done:
	if (graph)
		got_commit_graph_close(graph);
	free(obj_id);
	if (blob)
		got_object_blob_close(blob);
	if (start_commit)
		got_object_commit_close(start_commit);
	if (last_commit)
		got_object_commit_close(last_commit);
	if (err) {
		if (blame)
			blame_close(blame);
	} else
		*blamep = blame;

	return err;
}

const struct got_error *
got_blame(const char *path, struct got_object_id *commit_id,
    struct got_repository *repo, enum got_diff_algorithm diff_algo,
    got_blame_cb cb, void *arg, got_cancel_cb cancel_cb, void* cancel_arg,
    int fd1, int fd2, FILE *f1, FILE *f2)
{
	const struct got_error *err = NULL, *close_err = NULL;
	struct got_blame *blame;
	char *abspath;

	if (asprintf(&abspath, "%s%s", path[0] == '/' ? "" : "/", path) == -1)
		return got_error_from_errno2("asprintf", path);

	err = blame_open(&blame, abspath, commit_id, repo, diff_algo,
	    cb, arg, cancel_cb, cancel_arg, fd1, fd2, f1, f2);
	free(abspath);
	if (blame)
		close_err = blame_close(blame);
	return err ? err : close_err;
}
