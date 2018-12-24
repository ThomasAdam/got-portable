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
#include "got_opentemp.h"

#include "got_lib_diff.h"
#include "got_lib_path.h"
#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"

static const struct got_error *
diff_blobs(struct got_blob_object *blob1, struct got_blob_object *blob2,
    const char *label1, const char *label2, int diff_context, FILE *outfile,
    struct got_diff_changes *changes)
{
	struct got_diff_state ds;
	struct got_diff_args args;
	const struct got_error *err = NULL;
	FILE *f1 = NULL, *f2 = NULL;
	char hex1[SHA1_DIGEST_STRING_LENGTH];
	char hex2[SHA1_DIGEST_STRING_LENGTH];
	char *idstr1 = NULL, *idstr2 = NULL;
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
		err = got_object_blob_dump_to_file(&size1, NULL, f1, blob1);
		if (err)
			goto done;
	} else
		idstr1 = "/dev/null";

	size2 = 0;
	if (blob2) {
		idstr2 = got_object_blob_id_str(blob2, hex2, sizeof(hex2));
		err = got_object_blob_dump_to_file(&size2, NULL, f2, blob2);
		if (err)
			goto done;
	} else
		idstr2 = "/dev/null";

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
	args.diff_context = diff_context;
	flags |= D_PROTOTYPE;

	fprintf(outfile, "blob - %s\n", idstr1);
	fprintf(outfile, "blob + %s\n", idstr2);
	err = got_diffreg(&res, f1, f2, flags, &args, &ds, outfile, changes);
done:
	if (f1)
		fclose(f1);
	if (f2)
		fclose(f2);
	return err;
}

const struct got_error *
got_diff_blob(struct got_blob_object *blob1, struct got_blob_object *blob2,
    const char *label1, const char *label2, int diff_context, FILE *outfile)
{
	return diff_blobs(blob1, blob2, label1, label2, diff_context, outfile,
	    NULL);
}

const struct got_error *
got_diff_blob_lines_changed(struct got_diff_changes **changes,
    struct got_blob_object *blob1, struct got_blob_object *blob2)
{
	const struct got_error *err = NULL;

	*changes = calloc(1, sizeof(**changes));
	if (*changes == NULL)
		return got_error_from_errno();
	SIMPLEQ_INIT(&(*changes)->entries);

	err = diff_blobs(blob1, blob2, NULL, NULL, 3, NULL, *changes);
	if (err) {
		got_diff_free_changes(*changes);
		*changes = NULL;
	}
	return err;
}

void
got_diff_free_changes(struct got_diff_changes *changes)
{
	struct got_diff_change *change;
	while (!SIMPLEQ_EMPTY(&changes->entries)) {
		change = SIMPLEQ_FIRST(&changes->entries);
		SIMPLEQ_REMOVE_HEAD(&changes->entries, entry);
		free(change);
	}
	free(changes);
}

struct got_tree_entry *
match_entry_by_name(struct got_tree_entry *te1, struct got_tree_object *tree2)
{
	struct got_tree_entry *te2;
	const struct got_tree_entries *entries2;

	entries2 = got_object_tree_get_entries(tree2); 
	SIMPLEQ_FOREACH(te2, &entries2->head, entry) {
		if (strcmp(te1->name, te2->name) == 0)
			return te2;
	}
	return NULL;
}

static const struct got_error *
diff_added_blob(struct got_object_id *id, const char *label,
    int diff_context, struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err;
	struct got_blob_object  *blob = NULL;
	struct got_object *obj = NULL;

	err = got_object_open(&obj, repo, id);
	if (err)
		return err;

	err = got_object_blob_open(&blob, repo, obj, 8192);
	if (err)
		goto done;
	err = got_diff_blob(NULL, blob, NULL, label, diff_context, outfile);
done:
	got_object_close(obj);
	if (blob)
		got_object_blob_close(blob);
	return err;
}

static const struct got_error *
diff_modified_blob(struct got_object_id *id1, struct got_object_id *id2,
    const char *label1, const char *label2, int diff_context,
    struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err;
	struct got_object *obj1 = NULL;
	struct got_object *obj2 = NULL;
	struct got_blob_object *blob1 = NULL;
	struct got_blob_object *blob2 = NULL;

	err = got_object_open(&obj1, repo, id1);
	if (err)
		return err;
	if (obj1->type != GOT_OBJ_TYPE_BLOB) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = got_object_open(&obj2, repo, id2);
	if (err)
		goto done;
	if (obj2->type != GOT_OBJ_TYPE_BLOB) {
		err = got_error(GOT_ERR_BAD_OBJ_DATA);
		goto done;
	}

	err = got_object_blob_open(&blob1, repo, obj1, 8192);
	if (err)
		goto done;

	err = got_object_blob_open(&blob2, repo, obj2, 8192);
	if (err)
		goto done;

	err = got_diff_blob(blob1, blob2, label1, label2, diff_context,
	    outfile);

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
diff_deleted_blob(struct got_object_id *id, const char *label,
    int diff_context, struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err;
	struct got_blob_object  *blob = NULL;
	struct got_object *obj = NULL;

	err = got_object_open(&obj, repo, id);
	if (err)
		return err;

	err = got_object_blob_open(&blob, repo, obj, 8192);
	if (err)
		goto done;
	err = got_diff_blob(blob, NULL, label, NULL, diff_context, outfile);
done:
	got_object_close(obj);
	if (blob)
		got_object_blob_close(blob);
	return err;
}

static const struct got_error *
diff_added_tree(struct got_object_id *id, const char *label,
    int diff_context, struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err = NULL;
	struct got_object *treeobj = NULL;
	struct got_tree_object *tree = NULL;

	err = got_object_open(&treeobj, repo, id);
	if (err)
		goto done;

	if (treeobj->type != GOT_OBJ_TYPE_TREE) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = got_object_tree_open(&tree, repo, treeobj);
	if (err)
		goto done;

	err = got_diff_tree(NULL, tree, NULL, label, diff_context, repo,
	    outfile);

done:
	if (tree)
		got_object_tree_close(tree);
	if (treeobj)
		got_object_close(treeobj);
	return err;
}

static const struct got_error *
diff_modified_tree(struct got_object_id *id1, struct got_object_id *id2,
    const char *label1, const char *label2, int diff_context,
    struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err;
	struct got_object *treeobj1 = NULL;
	struct got_object *treeobj2 = NULL;
	struct got_tree_object *tree1 = NULL;
	struct got_tree_object *tree2 = NULL;

	err = got_object_open(&treeobj1, repo, id1);
	if (err)
		goto done;

	if (treeobj1->type != GOT_OBJ_TYPE_TREE) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = got_object_open(&treeobj2, repo, id2);
	if (err)
		goto done;

	if (treeobj2->type != GOT_OBJ_TYPE_TREE) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = got_object_tree_open(&tree1, repo, treeobj1);
	if (err)
		goto done;

	err = got_object_tree_open(&tree2, repo, treeobj2);
	if (err)
		goto done;

	err = got_diff_tree(tree1, tree2, label1, label2, diff_context, repo,
	    outfile);

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
diff_deleted_tree(struct got_object_id *id, const char *label,
    int diff_context, struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err;
	struct got_object *treeobj = NULL;
	struct got_tree_object *tree = NULL;

	err = got_object_open(&treeobj, repo, id);
	if (err)
		goto done;

	if (treeobj->type != GOT_OBJ_TYPE_TREE) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = got_object_tree_open(&tree, repo, treeobj);
	if (err)
		goto done;

	err = got_diff_tree(tree, NULL, label, NULL, diff_context, repo,
	    outfile);
done:
	if (tree)
		got_object_tree_close(tree);
	if (treeobj)
		got_object_close(treeobj);
	return err;
}

static const struct got_error *
diff_kind_mismatch(struct got_object_id *id1, struct got_object_id *id2,
    const char *label1, const char *label2, FILE *outfile)
{
	/* XXX TODO */
	return NULL;
}

static const struct got_error *
diff_entry_old_new(struct got_tree_entry *te1, struct got_tree_entry *te2,
    const char *label1, const char *label2, int diff_context,
    struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err = NULL;
	int id_match;

	if (te2 == NULL) {
		if (S_ISDIR(te1->mode))
			err = diff_deleted_tree(te1->id, label1, diff_context,
			    repo, outfile);
		else
			err = diff_deleted_blob(te1->id, label1, diff_context,
			    repo, outfile);
		return err;
	}

	id_match = (got_object_id_cmp(te1->id, te2->id) == 0);
	if (S_ISDIR(te1->mode) && S_ISDIR(te2->mode)) {
		if (!id_match)
			return diff_modified_tree(te1->id, te2->id,
			    label1, label2, diff_context, repo, outfile);
	} else if (S_ISREG(te1->mode) && S_ISREG(te2->mode)) {
		if (!id_match)
			return diff_modified_blob(te1->id, te2->id,
			    label1, label2, diff_context, repo, outfile);
	}

	if (id_match)
		return NULL;

	return diff_kind_mismatch(te1->id, te2->id, label1, label2, outfile);
}

static const struct got_error *
diff_entry_new_old(struct got_tree_entry *te2, struct got_tree_entry *te1,
    const char *label2, int diff_context, struct got_repository *repo,
    FILE *outfile)
{
	if (te1 != NULL) /* handled by diff_entry_old_new() */
		return NULL;

	if (S_ISDIR(te2->mode))
		return diff_added_tree(te2->id, label2, diff_context, repo,
		    outfile);

	return diff_added_blob(te2->id, label2, diff_context, repo, outfile);
}

const struct got_error *
got_diff_tree(struct got_tree_object *tree1, struct got_tree_object *tree2,
    const char *label1, const char *label2, int diff_context,
    struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err = NULL;
	struct got_tree_entry *te1 = NULL;
	struct got_tree_entry *te2 = NULL;
	char *l1 = NULL, *l2 = NULL;

	if (tree1) {
		const struct got_tree_entries *entries;
		entries = got_object_tree_get_entries(tree1);
		te1 = SIMPLEQ_FIRST(&entries->head);
		if (te1 && asprintf(&l1, "%s%s%s", label1, label1[0] ? "/" : "",
		    te1->name) == -1)
			return got_error_from_errno();
	}
	if (tree2) {
		const struct got_tree_entries *entries;
		entries = got_object_tree_get_entries(tree2);
		te2 = SIMPLEQ_FIRST(&entries->head);
		if (te2 && asprintf(&l2, "%s%s%s", label2, label2[0] ? "/" : "",
		    te2->name) == -1)
			return got_error_from_errno();
	}

	do {
		if (te1) {
			struct got_tree_entry *te = NULL;
			if (tree2)
				te = match_entry_by_name(te1, tree2);
			if (te) {
				free(l2);
				l2 = NULL;
				if (te && asprintf(&l2, "%s%s%s", label2,
				    label2[0] ? "/" : "", te->name) == -1)
					return got_error_from_errno();
			}
			err = diff_entry_old_new(te1, te, l1, l2, diff_context,
			    repo, outfile);
			if (err)
				break;
		}

		if (te2) {
			struct got_tree_entry *te = NULL;
			if (tree1)
				te = match_entry_by_name(te2, tree1);
			free(l2);
			if (te) {
				if (asprintf(&l2, "%s%s%s", label2,
				    label2[0] ? "/" : "", te->name) == -1)
					return got_error_from_errno();
			} else {
				if (asprintf(&l2, "%s%s%s", label2,
				    label2[0] ? "/" : "", te2->name) == -1)
					return got_error_from_errno();
			}
			err = diff_entry_new_old(te2, te, l2, diff_context,
			    repo, outfile);
			if (err)
				break;
		}

		free(l1);
		l1 = NULL;
		if (te1) {
			te1 = SIMPLEQ_NEXT(te1, entry);
			if (te1 &&
			    asprintf(&l1, "%s%s%s", label1,
			    label1[0] ? "/" : "", te1->name) == -1)
				return got_error_from_errno();
		}
		free(l2);
		l2 = NULL;
		if (te2) {
			te2 = SIMPLEQ_NEXT(te2, entry);
			if (te2 &&
			    asprintf(&l2, "%s%s%s", label2,
			        label2[0] ? "/" : "", te2->name) == -1)
				return got_error_from_errno();
		}
	} while (te1 || te2);

	return err;
}

const struct got_error *
got_diff_objects_as_blobs(struct got_object_id *id1, struct got_object_id *id2,
    const char *label1, const char *label2, int diff_context,
    struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err;
	struct got_blob_object *blob1 = NULL, *blob2 = NULL;

	if (id1 == NULL && id2 == NULL)
		return got_error(GOT_ERR_NO_OBJ);

	if (id1) {
		err = got_object_open_as_blob(&blob1, repo, id1, 8192);
		if (err)
			goto done;
	}
	if (id2) {
		err = got_object_open_as_blob(&blob2, repo, id2, 8192);
		if (err)
			goto done;
	}
	err = got_diff_blob(blob1, blob2, label1, label2, diff_context,
	    outfile);
done:
	if (blob1)
		got_object_blob_close(blob1);
	if (blob2)
		got_object_blob_close(blob2);
	return err;
}

const struct got_error *
got_diff_objects_as_trees(struct got_object_id *id1, struct got_object_id *id2,
    char *label1, char *label2, int diff_context, struct got_repository *repo,
    FILE *outfile)
{
	const struct got_error *err;
	struct got_tree_object *tree1 = NULL, *tree2 = NULL;

	if (id1 == NULL && id2 == NULL)
		return got_error(GOT_ERR_NO_OBJ);

	if (id1) {
		err = got_object_open_as_tree(&tree1, repo, id1);
		if (err)
			goto done;
	}
	if (id2) {
		err = got_object_open_as_tree(&tree2, repo, id2);
		if (err)
			goto done;
	}
	err = got_diff_tree(tree1, tree2, label1, label2, diff_context,
	   repo, outfile);
done:
	if (tree1)
		got_object_tree_close(tree1);
	if (tree2)
		got_object_tree_close(tree2);
	return err;
}

const struct got_error *
got_diff_objects_as_commits(struct got_object_id *id1,
    struct got_object_id *id2, int diff_context,
    struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err;
	struct got_commit_object *commit1 = NULL, *commit2 = NULL;

	if (id2 == NULL)
		return got_error(GOT_ERR_NO_OBJ);

	if (id1) {
		err = got_object_open_as_commit(&commit1, repo, id1);
		if (err)
			goto done;
	}

	err = got_object_open_as_commit(&commit2, repo, id2);
	if (err)
		goto done;

	err = got_diff_objects_as_trees(
	    commit1 ? got_object_commit_get_tree_id(commit1) : NULL,
	    got_object_commit_get_tree_id(commit2), "", "", diff_context, repo,
	    outfile);
done:
	if (commit1)
		got_object_commit_close(commit1);
	if (commit2)
		got_object_commit_close(commit2);
	return err;
}
