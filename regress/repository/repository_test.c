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

#include "got_error.h"
#include "got_object.h"
#include "got_refs.h"
#include "got_repository.h"

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
	printf("object type=%d size=%lu\n", obj->type, obj->size);
	if (obj->type == GOT_OBJ_TYPE_COMMIT)
		print_commit_object(obj, repo);
	got_object_close(obj);
	free(id);
	got_ref_close(head_ref);
	got_repo_close(repo);
	return 1;
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

	return failure ? 1 : 0;
}
