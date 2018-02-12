/*
 * Copyright (c) 2017 Stefan Sperling <stsp@openbsd.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sha1.h>
#include <zlib.h>

#include "got_repository.h"
#include "got_object.h"
#include "got_error.h"
#include "got_diff.h"

#include "diff.h"
#include "path.h"

const struct got_error *
got_diff_blob(struct got_blob_object *blob1, struct got_blob_object *blob2,
    const char *label1, const char *label2, FILE *outfile)
{
	struct got_diff_state ds;
	struct got_diff_args args;
	const struct got_error *err = NULL;
	FILE *f1 = NULL, *f2 = NULL;
	char hex1[SHA1_DIGEST_STRING_LENGTH];
	char hex2[SHA1_DIGEST_STRING_LENGTH];
	char *idstr1 = NULL, *idstr2 = NULL;
	size_t len, hdrlen;
	size_t size1, size2;
	int res, flags = 0;

	if (blob1) {
		f1 = got_opentemp();
		if (f1 == NULL)
			return got_error(GOT_ERR_FILE_OPEN);
	} else
		flags |= D_EMPTY1;

	if (blob2) {
		f2 = got_opentemp();
		if (f2 == NULL) {
			fclose(f1);
			return got_error(GOT_ERR_FILE_OPEN);
		}
	} else
		flags |= D_EMPTY2;

	size1 = 0;
	if (blob1) {
		idstr1 = got_object_blob_id_str(blob1, hex1, sizeof(hex1));
		hdrlen = got_object_blob_get_hdrlen(blob1);
		do {
			err = got_object_blob_read_block(&len, blob1);
			if (err)
				goto done;
			if (len == 0)
				break;
			size1 += len;
			/* Skip blob object header first time around. */
			fwrite(got_object_blob_get_read_buf(blob1) + hdrlen, len - hdrlen, 1, f1);
			hdrlen = 0;
		} while (len != 0);
	} else
		idstr1 = "/dev/null";

	size2 = 0;
	if (blob2) {
		idstr2 = got_object_blob_id_str(blob2, hex2, sizeof(hex2));
		hdrlen = got_object_blob_get_hdrlen(blob2);
		do {
			err = got_object_blob_read_block(&len, blob2);
			if (err)
				goto done;
			if (len == 0)
				break;
			size2 += len;
			/* Skip blob object header first time around. */
			fwrite(got_object_blob_get_read_buf(blob2) + hdrlen, len - hdrlen, 1, f2);
			hdrlen = 0;
		} while (len != 0);
	} else
		idstr2 = "/dev/null";

	if (f1) {
		fflush(f1);
		rewind(f1);
	}
	if (f2) {
		fflush(f2);
		rewind(f2);
	}

	memset(&ds, 0, sizeof(ds));
	/* XXX should stat buffers be passed in args instead of ds? */
	ds.stb1.st_mode = S_IFREG;
	if (blob1)
		ds.stb1.st_size = size1;
	ds.stb1.st_mtime = 0; /* XXX */

	ds.stb2.st_mode = S_IFREG;
	if (blob2)
		ds.stb2.st_size = size2;
	ds.stb2.st_mtime = 0; /* XXX */

	memset(&args, 0, sizeof(args));
	args.diff_format = D_UNIFIED;
	args.label[0] = label1 ? label1 : idstr1;
	args.label[1] = label2 ? label2 : idstr2;

	err = got_diffreg(&res, f1, f2, flags, &args, &ds, outfile);
done:
	if (f1)
		fclose(f1);
	if (f2)
		fclose(f2);
	return err;
}

struct got_tree_entry *
match_entry_by_name(struct got_tree_entry *te1, struct got_tree_object *tree2)
{
	struct got_tree_entry *te2;

	SIMPLEQ_FOREACH(te2, &tree2->entries, entry) {
		if (strcmp(te1->name, te2->name) == 0)
			return te2;
	}
	return NULL;
}

static const struct got_error *
diff_added_blob(struct got_object_id *id, struct got_repository *repo,
    FILE *outfile)
{
	const struct got_error *err;
	struct got_blob_object  *blob;
	struct got_object *obj;

	err = got_object_open(&obj, repo, id);
	if (err)
		return err;
	err = got_object_blob_open(&blob, repo, obj, 8192);
	if (err != NULL)
		return err;

	return got_diff_blob(NULL, blob, NULL, NULL, outfile);
}

static const struct got_error *
diff_modified_blob(struct got_object_id *id1, struct got_object_id *id2,
    struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err;
	struct got_object *obj1 = NULL;
	struct got_object *obj2 = NULL;
	struct got_blob_object *blob1 = NULL;
	struct got_blob_object *blob2 = NULL;

	err = got_object_open(&obj1, repo, id1);
	if (err)
		return got_error(GOT_ERR_BAD_OBJ_HDR);
	if (got_object_get_type(obj1) != GOT_OBJ_TYPE_BLOB) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = got_object_open(&obj2, repo, id2);
	if (err) {
		err= got_error(GOT_ERR_BAD_OBJ_HDR);
		goto done;
	}
	if (got_object_get_type(obj2) != GOT_OBJ_TYPE_BLOB) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}

	err = got_object_blob_open(&blob1, repo, obj1, 8192);
	if (err != NULL) {
		err = got_error(GOT_ERR_FILE_OPEN);
		goto done;
	}

	err = got_object_blob_open(&blob2, repo, obj2, 8192);
	if (err != NULL) {
		err = got_error(GOT_ERR_FILE_OPEN);
		goto done;
	}

	err = got_diff_blob(blob1, blob2, NULL, NULL, outfile);

done:
	if (obj1)
		got_object_close(obj1);
	if (obj2)
		got_object_close(obj2);
	if (blob1)
		got_object_blob_close(blob1);
	if (blob2)
		got_object_blob_close(blob2);
	return err;
}

static const struct got_error *
diff_deleted_blob(struct got_object_id *id, struct got_repository *repo,
    FILE *outfile)
{
	const struct got_error *err;
	struct got_blob_object  *blob;
	struct got_object *obj;

	err = got_object_open(&obj, repo, id);
	if (err)
		return err;
	err = got_object_blob_open(&blob, repo, obj, 8192);
	if (err != NULL)
		return err;

	return got_diff_blob(blob, NULL, NULL, NULL, outfile);
}

static const struct got_error *
diff_added_tree(struct got_object_id *id, struct got_repository *repo,
    FILE *outfile)
{
	const struct got_error *err = NULL;
	struct got_object *treeobj = NULL;
	struct got_tree_object *tree = NULL;

	err = got_object_open(&treeobj, repo, id);
	if (err)
		goto done;

	if (got_object_get_type(treeobj) != GOT_OBJ_TYPE_TREE) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = got_object_tree_open(&tree, repo, treeobj);
	if (err)
		goto done;

	err = got_diff_tree(NULL, tree, repo, outfile);

done:
	if (tree)
		got_object_tree_close(tree);
	if (treeobj)
		got_object_close(treeobj);
	return err;
}

static const struct got_error *
diff_modified_tree(struct got_object_id *id1, struct got_object_id *id2,
    struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err = NULL;
	struct got_object *treeobj1 = NULL;
	struct got_object *treeobj2 = NULL;
	struct got_tree_object *tree1 = NULL;
	struct got_tree_object *tree2 = NULL;

	err = got_object_open(&treeobj1, repo, id1);
	if (err)
		goto done;

	if (got_object_get_type(treeobj1) != GOT_OBJ_TYPE_TREE) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = got_object_open(&treeobj2, repo, id2);
	if (err)
		goto done;

	if (got_object_get_type(treeobj2) != GOT_OBJ_TYPE_TREE) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = got_object_tree_open(&tree1, repo, treeobj1);
	if (err)
		goto done;

	err = got_object_tree_open(&tree2, repo, treeobj2);
	if (err)
		goto done;

	err = got_diff_tree(tree1, tree2, repo, outfile);

done:
	if (tree1)
		got_object_tree_close(tree1);
	if (tree2)
		got_object_tree_close(tree2);
	if (treeobj1)
		got_object_close(treeobj1);
	if (treeobj2)
		got_object_close(treeobj2);
	return err;
}

static const struct got_error *
diff_deleted_tree(struct got_object_id *id, struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err = NULL;
	struct got_object *treeobj = NULL;
	struct got_tree_object *tree = NULL;

	err = got_object_open(&treeobj, repo, id);
	if (err)
		goto done;

	if (got_object_get_type(treeobj) != GOT_OBJ_TYPE_TREE) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = got_object_tree_open(&tree, repo, treeobj);
	if (err)
		goto done;

	err = got_diff_tree(tree, NULL, repo, outfile);

done:
	if (tree)
		got_object_tree_close(tree);
	if (treeobj)
		got_object_close(treeobj);
	return err;
}

static const struct got_error *
diff_kind_mismatch(struct got_object_id *id1, struct got_object_id *id2,
    FILE *outfile)
{
	/* XXX TODO */
	return NULL;
}

static const struct got_error *
diff_entry_old_new(struct got_tree_entry *te1, struct got_tree_object *tree2,
    struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err;
	struct got_tree_entry *te2;
	char hex[SHA1_DIGEST_STRING_LENGTH];

	te2 = match_entry_by_name(te1, tree2);
	if (te2 == NULL) {
		if (S_ISDIR(te1->mode))
			return diff_deleted_tree(&te1->id, repo, outfile);
		return diff_deleted_blob(&te1->id, repo, outfile);
	}

	if (S_ISDIR(te1->mode) && S_ISDIR(te2->mode)) {
		if (got_object_id_cmp(&te1->id, &te2->id) != 0)
			return diff_modified_tree(&te1->id, &te2->id, repo,
			    outfile);
	} else if (S_ISREG(te1->mode) && S_ISREG(te2->mode)) {
		if (got_object_id_cmp(&te1->id, &te2->id) != 0)
			return diff_modified_blob(&te1->id, &te2->id, repo,
			    outfile);
	}

	return diff_kind_mismatch(&te1->id, &te2->id, outfile);
}

static const struct got_error *
diff_entry_new_old(struct got_tree_entry *te2, struct got_tree_object *tree1,
    struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err;
	struct got_tree_entry *te1;

	te1 = match_entry_by_name(te2, tree1);
	if (te1 != NULL) /* handled by diff_entry_old_new() */
		return NULL;

	if (S_ISDIR(te2->mode))
		return diff_added_tree(&te2->id, repo, outfile);
	return diff_added_blob(&te2->id, repo, outfile);
}

const struct got_error *
got_diff_tree(struct got_tree_object *tree1, struct got_tree_object *tree2,
    struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err = NULL;
	struct got_tree_entry *te1 = NULL;
	struct got_tree_entry *te2 = NULL;

	if (tree1)
		te1 = SIMPLEQ_FIRST(&tree1->entries);
	if (tree2)
		te2 = SIMPLEQ_FIRST(&tree2->entries);

	do {
		if (te1) {
			err = diff_entry_old_new(te1, tree2, repo, outfile);
			if (err)
				break;
		}

		if (te2) {
			err = diff_entry_new_old(te2, tree1, repo, outfile);
			if (err)
				break;
		}

		if (te1)
			te1 = SIMPLEQ_NEXT(te1, entry);
		if (te2)
			te2 = SIMPLEQ_NEXT(te2, entry);
	} while (te1 || te2);

	return err;
}
