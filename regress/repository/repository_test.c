#include <stdio.h>
#include <stdlib.h>
#include <sha1.h>

#include "got_error.h"
#include "got_path.h"
#include "got_refs.h"
#include "got_repository.h"

#define RUN_TEST(expr, name) \
	if (!(expr)) { printf("test %s failed", (name)); failure = 1; }

#define GOT_REPO_PATH "../../../"

static int
repo_open_test(const char *repo_path)
{
	const struct got_error *err;
	struct got_repository *repo;
	const char *abspath;
	int ret;

	abspath = got_path_normalize(repo_path);
	err = got_repo_open(&repo, abspath);
	ret = (err == NULL && repo != NULL);
	got_repo_close(repo);
	return ret;
}

static int
repo_get_head_ref(const char *repo_path)
{
	const struct got_error *err;
	struct got_repository *repo;
	struct got_reference *head_ref;
	const char *abspath;
	int ret;

	abspath = got_path_normalize(repo_path);
	err = got_repo_open(&repo, abspath);
	if (err != NULL || repo == NULL)
		return 0;
	err = got_repo_get_reference(&head_ref, repo, GOT_REF_HEAD);
	if (err != NULL || head_ref == NULL)
		return 0;
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

	RUN_TEST(repo_open_test(repo_path), "repo_open");
	RUN_TEST(repo_get_head_ref(repo_path), "get_head_ref");

	return failure ? 1 : 0;
}
