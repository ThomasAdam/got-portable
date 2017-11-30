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

#include <sys/stat.h>
#include <sys/queue.h>

#include <stdio.h>
#include <stdlib.h>
#include <sha1.h>
#include <zlib.h>

#include "got_error.h"
#include "got_object.h"
#include "got_refs.h"
#include "got_repository.h"
#include "got_sha1.h"
#include "got_diff.h"

#define RUN_TEST(expr, name) \
	if (!(expr)) { printf("test %s failed", (name)); failure = 1; }

#define GOT_REPO_PATH "../../../"

static const struct got_error *
print_commit_object(struct got_object *, struct got_repository *);

static const struct got_error *
print_parent_commits(struct got_commit_object *commit,
    struct got_repository *repo)
{
	struct got_parent_id *pid;
	const struct got_error *err;
	struct got_object *obj;

	SIMPLEQ_FOREACH(pid, &commit->parent_ids, entry) {
		err = got_object_open(&obj, repo, &pid->id);
		if (err != NULL)
			return err;
		if (obj->type != GOT_OBJ_TYPE_COMMIT)
			return got_error(GOT_ERR_OBJ_TYPE);
		print_commit_object(obj, repo);
		got_object_close(obj);
	}

	return NULL;
}

static const struct got_error *
print_tree_object(struct got_object *obj, char *parent,
    struct got_repository *repo)
{
	struct got_tree_object *tree;
	struct got_tree_entry *te;
	const struct got_error *err;
	char hex[SHA1_DIGEST_STRING_LENGTH];

	err = got_object_tree_open(&tree, repo, obj);
	if (err != NULL)
		return err;

	SIMPLEQ_FOREACH(te, &tree->entries, entry) {
		struct got_object *treeobj;
		char *next_parent;

		if (!S_ISDIR(te->mode)) {
			printf("%s %s/%s\n",
			    got_object_id_str(&te->id, hex, sizeof(hex)),
			    parent, te->name);
			continue;
		}
		printf("%s %s/%s\n",
		    got_object_id_str(&te->id, hex, sizeof(hex)),
		    parent, te->name);

		err = got_object_open(&treeobj, repo, &te->id);
		if (err != NULL)
			break;

		if (treeobj->type != GOT_OBJ_TYPE_TREE) {
			err = got_error(GOT_ERR_OBJ_TYPE);
			got_object_close(treeobj);
			break;
		}

		if (asprintf(&next_parent, "%s/%s", parent, te->name) == -1) {
			err = got_error(GOT_ERR_NO_MEM);
			got_object_close(treeobj);
			break;
		}

		err = print_tree_object(treeobj, next_parent, repo);
		free(next_parent);
		if (err) {
			got_object_close(treeobj);
			break;
		}

		got_object_close(treeobj);
	}

	got_object_tree_close(tree);
	return err;
}

static const struct got_error *
print_commit_object(struct got_object *obj, struct got_repository *repo)
{
	struct got_commit_object *commit;
	struct got_parent_id *pid;
	char buf[SHA1_DIGEST_STRING_LENGTH];
	const struct got_error *err;
	struct got_object* treeobj;

	err = got_object_commit_open(&commit, repo, obj);
	if (err != NULL)
		return err;

	printf("tree: %s\n",
	    got_object_id_str(&commit->tree_id, buf, sizeof(buf)));
	printf("parent%s: ", (commit->nparents == 1) ? "" : "s");
	SIMPLEQ_FOREACH(pid, &commit->parent_ids, entry) {
		printf("%s\n",
		    got_object_id_str(&pid->id, buf, sizeof(buf)));
	}
	printf("author: %s\n", commit->author);
	printf("committer: %s\n", commit->committer);
	printf("log: %s\n", commit->logmsg);

	err = got_object_open(&treeobj, repo, &commit->tree_id);
	if (err != NULL)
		return err;
	if (treeobj->type == GOT_OBJ_TYPE_TREE) {
		print_tree_object(treeobj, "", repo);
		printf("\n");
	}
	got_object_close(treeobj);

	err = print_parent_commits(commit, repo);
	got_object_commit_close(commit);

	return err;
}

static int
repo_read_log(const char *repo_path)
{
	const struct got_error *err;
	struct got_repository *repo;
	struct got_reference *head_ref;
	struct got_object_id *id;
	struct got_object *obj;
	char buf[SHA1_DIGEST_STRING_LENGTH];
	int ret;

	err = got_repo_open(&repo, repo_path);
	if (err != NULL || repo == NULL)
		return 0;
	err = got_ref_open(&head_ref, repo, GOT_REF_HEAD);
	if (err != NULL || head_ref == NULL)
		return 0;
	err = got_ref_resolve(&id, repo, head_ref);
	if (err != NULL || head_ref == NULL)
		return 0;
	printf("HEAD is at %s\n", got_object_id_str(id, buf, sizeof(buf)));
	err = got_object_open(&obj, repo, id);
	if (err != NULL || obj == NULL)
		return 0;
	if (obj->type == GOT_OBJ_TYPE_COMMIT)
		print_commit_object(obj, repo);
	got_object_close(obj);
	free(id);
	got_ref_close(head_ref);
	got_repo_close(repo);
	return 1;
}

static int
repo_read_blob(const char *repo_path)
{
	const char *blob_sha1 = "141f5fdc96126c1f4195558560a3c915e3d9b4c3";
	const struct got_error *err;
	struct got_repository *repo;
	struct got_object_id id;
	struct got_object *obj;
	struct got_blob_object *blob;
	char hex[SHA1_DIGEST_STRING_LENGTH];
	int i;
	size_t len;

	if (!got_parse_sha1_digest(id.sha1, blob_sha1))
		return 0;

	err = got_repo_open(&repo, repo_path);
	if (err != NULL || repo == NULL)
		return 0;
	err = got_object_open(&obj, repo, &id);
	if (err != NULL || obj == NULL)
		return 0;
	if (obj->type != GOT_OBJ_TYPE_BLOB)
		return 0;

	err = got_object_blob_open(&blob, repo, obj, 64);
	if (err != NULL)
		return 0;

	putchar('\n');
	do {
		err = got_object_blob_read_block(blob, &len);
		if (err)
			break;
		for (i = 0; i < len; i++)
			putchar(blob->zb.outbuf[i]);
	} while (len != 0);
	putchar('\n');

	got_object_blob_close(blob);
	got_object_close(obj);
	got_repo_close(repo);
	return (err == NULL);
}

static int
repo_diff_blob(const char *repo_path)
{
	const char *blob1_sha1 = "141f5fdc96126c1f4195558560a3c915e3d9b4c3";
	const char *blob2_sha1 = "de7eb21b21c7823a753261aadf7cba35c9580fbf";
	const struct got_error *err;
	struct got_repository *repo;
	struct got_object_id id1;
	struct got_object_id id2;
	struct got_object *obj1;
	struct got_object *obj2;
	struct got_blob_object *blob1;
	struct got_blob_object *blob2;
	char hex[SHA1_DIGEST_STRING_LENGTH];
	int i;
	size_t len;

	if (!got_parse_sha1_digest(id1.sha1, blob1_sha1))
		return 0;
	if (!got_parse_sha1_digest(id2.sha1, blob2_sha1))
		return 0;

	err = got_repo_open(&repo, repo_path);
	if (err != NULL || repo == NULL)
		return 0;

	err = got_object_open(&obj1, repo, &id1);
	if (err != NULL || obj1 == NULL)
		return 0;
	if (obj1->type != GOT_OBJ_TYPE_BLOB)
		return 0;
	err = got_object_open(&obj2, repo, &id2);
	if (err != NULL || obj2 == NULL)
		return 0;
	if (obj2->type != GOT_OBJ_TYPE_BLOB)
		return 0;

	err = got_object_blob_open(&blob1, repo, obj1, 512);
	if (err != NULL)
		return 0;

	err = got_object_blob_open(&blob2, repo, obj2, 512);
	if (err != NULL)
		return 0;

	putchar('\n');
	got_diff_blob(blob1, blob2, NULL, NULL, stdout);
	putchar('\n');

	got_object_blob_close(blob1);
	got_object_blob_close(blob2);
	got_object_close(obj1);
	got_object_close(obj2);
	got_repo_close(repo);
	return (err == NULL);
}

static int
repo_diff_tree(const char *repo_path)
{
	const char *tree1_sha1 = "1efc41caf761a0a1f119d0c5121eedcb2e7a88c3";
	const char *tree2_sha1 = "cb4ba67a335b2b7ecac88867063596bd9e1ab485";
	const struct got_error *err;
	struct got_repository *repo;
	struct got_object_id id1;
	struct got_object_id id2;
	struct got_object *obj1;
	struct got_object *obj2;
	struct got_tree_object *tree1;
	struct got_tree_object *tree2;
	char hex[SHA1_DIGEST_STRING_LENGTH];
	int i;
	size_t len;

	if (!got_parse_sha1_digest(id1.sha1, tree1_sha1))
		return 0;
	if (!got_parse_sha1_digest(id2.sha1, tree2_sha1))
		return 0;

	err = got_repo_open(&repo, repo_path);
	if (err != NULL || repo == NULL)
		return 0;

	err = got_object_open(&obj1, repo, &id1);
	if (err != NULL || obj1 == NULL)
		return 0;
	if (obj1->type != GOT_OBJ_TYPE_TREE)
		return 0;
	err = got_object_open(&obj2, repo, &id2);
	if (err != NULL || obj2 == NULL)
		return 0;
	if (obj2->type != GOT_OBJ_TYPE_TREE)
		return 0;

	err = got_object_tree_open(&tree1, repo, obj1);
	if (err != NULL)
		return 0;

	err = got_object_tree_open(&tree2, repo, obj2);
	if (err != NULL)
		return 0;

	putchar('\n');
	got_diff_tree(tree1, tree2, repo);
	putchar('\n');

	got_object_tree_close(tree1);
	got_object_tree_close(tree2);
	got_object_close(obj1);
	got_object_close(obj2);
	got_repo_close(repo);
	return (err == NULL);
}

int
main(int argc, const char *argv[])
{
	int failure = 0;
	const char *repo_path;

	if (argc == 1)
		repo_path = GOT_REPO_PATH;
	else if (argc == 2)
		repo_path = argv[1];
	else {
		fprintf(stderr, "usage: repository_test [REPO_PATH]\n");
		return 1;
	}

	RUN_TEST(repo_read_log(repo_path), "read_log");
	RUN_TEST(repo_read_blob(repo_path), "read_blob");
	RUN_TEST(repo_diff_blob(repo_path), "diff_blob");
	RUN_TEST(repo_diff_tree(repo_path), "diff_tree");

	return failure ? 1 : 0;
}
