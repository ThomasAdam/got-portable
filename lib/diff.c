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
#include <sha1.h>
#include <zlib.h>

#include "got_repository.h"
#include "got_object.h"
#include "got_error.h"

#include "diff.h"

static const struct got_error *
open_tempfile(FILE **sfp, char **sfn)
{
	static const int sfnlen = 20;
	int fd;

	*sfn = calloc(sfnlen, sizeof(char));
	if (*sfn == NULL)
		return got_error(GOT_ERR_NO_MEM);
	strlcpy(*sfn, "/tmp/got.XXXXXXXXXX", sfnlen);
	if ((fd = mkstemp(*sfn)) == -1 ||
	    ((*sfp) = fdopen(fd, "w+")) == NULL) {
		if (fd != -1) {
			unlink(*sfn);
			close(fd);
		}
		free(*sfn);
		return got_error(GOT_ERR_FILE_OPEN);
	}
	return NULL;
}

const struct got_error *
got_diff_blob(struct got_blob_object *blob1, struct got_blob_object *blob2,
    const char *label1, const char *label2, FILE *outfile)
{
	struct got_diff_state ds;
	struct got_diff_args args;
	const struct got_error *err = NULL;
	FILE *f1, *f2;
	char *n1, *n2;
	size_t len, hdrlen;
	char hex1[SHA1_DIGEST_STRING_LENGTH];
	char hex2[SHA1_DIGEST_STRING_LENGTH];
	int res;

	err = open_tempfile(&f1, &n1);
	if (err != NULL)
		return err;

	err = open_tempfile(&f2, &n2);
	if (err != NULL) {
		fclose(f1);
		free(n1);
		return err;
	}


	hdrlen = blob1->hdrlen;
	do {
		err = got_object_blob_read_block(blob1, &len);
		if (err)
			goto done;
		/* Skip blob object header first time around. */
		fwrite(blob1->zb.outbuf + hdrlen, len - hdrlen, 1, f1);
		hdrlen = 0;
	} while (len != 0);

	hdrlen = blob2->hdrlen;
	do {
		err = got_object_blob_read_block(blob2, &len);
		if (err)
			goto done;
		/* Skip blob object header first time around. */
		fwrite(blob2->zb.outbuf + hdrlen, len - hdrlen, 1, f2);
		hdrlen = 0;
	} while (len != 0);

	fflush(f1);
	fflush(f2);

	memset(&ds, 0, sizeof(ds));
	memset(&args, 0, sizeof(args));

	args.diff_format = D_UNIFIED;
	args.label[0] = label1 ?
	    label1 : got_object_id_str(&blob1->id, hex1, sizeof(hex1));
	args.label[1] = label2 ?
	    label2 : got_object_id_str(&blob2->id, hex2, sizeof(hex2));

	err = got_diffreg(&res, n1, n2, 0, &args, &ds);
done:
	unlink(n1);
	unlink(n2);
	fclose(f1);
	fclose(f2);
	free(n1);
	free(n2);
	return err;
}

static const struct got_error *
match_entry_by_name(struct got_tree_entry **te, struct got_tree_entry *te1,
    struct got_tree_object *tree2)
{
	*te = NULL;
	return NULL;
}

static int
same_id(struct got_object_id *id1, struct got_object_id *id2)
{
	return (memcmp(id1->sha1, id2->sha1, SHA1_DIGEST_LENGTH) == 0);
}

static const struct got_error *
diff_added_blob(struct got_object_id *id)
{
	return NULL;
}

static const struct got_error *
diff_modified_blob(struct got_object_id *id1, struct got_object_id *id2)
{
	return NULL;
}

static const struct got_error *
diff_deleted_blob(struct got_object_id *id)
{
	return NULL;
}

static const struct got_error *
diff_added_tree(struct got_object_id *id)
{
	return NULL;
}

static const struct got_error *
diff_modified_tree(struct got_object_id *id1, struct got_object_id *id2)
{
	return NULL;
}

static const struct got_error *
diff_deleted_tree(struct got_object_id *id)
{
	return NULL;
}

static const struct got_error *
diff_kind_mismatch(struct got_object_id *id1, struct got_object_id *id2)
{
	return NULL;
}

static const struct got_error *
diff_entry_old_new(struct got_tree_entry *te1, struct got_tree_object *tree2)
{
	const struct got_error *err;
	struct got_tree_entry *te2;

	err = match_entry_by_name(&te2, te1, tree2);
	if (err)
		return err;
	if (te2 == NULL) {
		if (S_ISDIR(te1->mode))
			return diff_deleted_tree(&te1->id);
		return diff_deleted_blob(&te1->id);
	}

	if (S_ISDIR(te1->mode) && S_ISDIR(te2->mode)) {
		if (!same_id(&te1->id, &te2->id))
			return diff_modified_tree(&te1->id, &te2->id);
	} else if (S_ISREG(te1->mode) && S_ISREG(te2->mode)) {
		if (!same_id(&te1->id, &te2->id))
			return diff_modified_blob(&te1->id, &te2->id);
	}

	return diff_kind_mismatch(&te1->id, &te2->id);
}

static const struct got_error *
diff_entry_new_old(struct got_tree_entry *te2, struct got_tree_object *tree1)
{
	const struct got_error *err;
	struct got_tree_entry *te1;

	err = match_entry_by_name(&te1, te2, tree1);
	if (err)
		return err;
	if (te1 != NULL) /* handled by diff_entry_old_new() */
		return NULL;

	if (S_ISDIR(te2->mode))
		return diff_added_tree(&te2->id);
	return diff_added_blob(&te2->id);
}

const struct got_error *
got_diff_tree(struct got_tree_object *tree1, struct got_tree_object *tree2,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_tree_entry *te1;
	struct got_tree_entry *te2;

	if (tree1->nentries == 0 && tree2->nentries == 0)
		return NULL;

	te1 = SIMPLEQ_FIRST(&tree1->entries);
	te2 = SIMPLEQ_FIRST(&tree2->entries);

	do {
		if (te1) {
			err = diff_entry_old_new(te1, tree2);
			if (err)
				break;
		}

		if (te2) {
			err = diff_entry_new_old(te2, tree1);
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
