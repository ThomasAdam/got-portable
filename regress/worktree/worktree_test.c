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

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/limits.h>
#include <sys/stat.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <util.h>
#include <err.h>
#include <unistd.h>
#include <uuid.h>

#include "got_error.h"
#include "got_object.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_path.h"
#include "got_worktree.h"
#include "got_opentemp.h"
#include "got_privsep.h"

#include "got_lib_worktree.h"

#define GOT_REPO_PATH "../../../"

static int verbose;

void
test_printf(char *fmt, ...)
{
	va_list ap;

	if (!verbose)
		return;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

static int
remove_got_dir(const char *worktree_path)
{
	char *path;

	if (asprintf(&path, "%s/%s", worktree_path, GOT_WORKTREE_GOT_DIR) == -1)
		return 0;
	rmdir(path);
	free(path);
	return 1;
}

static int
remove_meta_file(const char *worktree_path, const char *name)
{
	char *path;

	if (asprintf(&path, "%s/%s/%s", worktree_path, GOT_WORKTREE_GOT_DIR,
	    name) == -1)
		return 0;
	unlink(path);
	free(path);
	return 1;
}

static const struct got_error *
remove_worktree_base_ref(struct got_worktree *worktree,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_reference *base_ref = NULL;
	char *refname = NULL, *absrefname = NULL;

	err = got_worktree_get_base_ref_name(&refname, worktree);
	if (err)
		return err;

	if (asprintf(&absrefname, "refs/%s", refname) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	err = got_ref_open(&base_ref, repo, absrefname, 0);
	if (err)
		goto done;

	err = got_ref_delete(base_ref, repo);
done:
	if (base_ref)
		got_ref_close(base_ref);
	free(refname);
	free(absrefname);
	return err;

}

static int
remove_worktree(const char *worktree_path)
{
	if (!remove_meta_file(worktree_path, GOT_WORKTREE_HEAD_REF))
		return 0;
	if (!remove_meta_file(worktree_path, GOT_WORKTREE_BASE_COMMIT))
		return 0;
	if (!remove_meta_file(worktree_path, GOT_WORKTREE_FILE_INDEX))
		return 0;
	if (!remove_meta_file(worktree_path, GOT_WORKTREE_REPOSITORY))
		return 0;
	if (!remove_meta_file(worktree_path, GOT_WORKTREE_PATH_PREFIX))
		return 0;
	if (!remove_meta_file(worktree_path, GOT_WORKTREE_LOCK))
		return 0;
	if (!remove_meta_file(worktree_path, GOT_WORKTREE_FORMAT))
		return 0;
	if (!remove_meta_file(worktree_path, GOT_WORKTREE_UUID))
		return 0;
	if (!remove_got_dir(worktree_path))
		return 0;
	if (rmdir(worktree_path) == -1)
		return 0;
	return 1;
}

static int
read_meta_file(char **content, const char *path)
{
	FILE *f;
	size_t len;
	const char delim[3] = {'\0', '\0', '\0'};
	int ret = 0;

	f = fopen(path, "r");
	if (f == NULL)
		return errno;

	*content = fparseln(f, &len, NULL, delim, 0);
	if (*content == NULL)
		ret = errno;
	if (fclose(f) != 0 && ret == 0)
		ret = errno;
	return ret;
}

static int
check_meta_file_exists(const char *worktree_path, const char *name)
{
	struct stat sb;
	char *path;
	int ret = 0;

	if (asprintf(&path, "%s/%s/%s", worktree_path, GOT_WORKTREE_GOT_DIR,
	    name) == -1)
		return 0;
	if (stat(path, &sb) == 0)
		ret = 1;
	if (verbose) {
		char *content;
		if (read_meta_file(&content, path) == 0) {
			test_printf("%s:\t%s\n", name, content);
			free(content);
		}
	}
	free(path);
	return ret;
}

static int
worktree_init(const char *repo_path)
{
	const struct got_error *err;
	struct got_repository *repo = NULL;
	struct got_reference *head_ref = NULL;
	char worktree_path[PATH_MAX];
	int ok = 0;

	err = got_repo_open(&repo, repo_path);
	if (err != NULL || repo == NULL)
		goto done;
	err = got_ref_open(&head_ref, repo, GOT_REF_HEAD, 0);
	if (err != NULL || head_ref == NULL)
		goto done;

	strlcpy(worktree_path, "worktree-XXXXXX", sizeof(worktree_path));
	if (mkdtemp(worktree_path) == NULL)
		goto done;

	err = got_worktree_init(worktree_path, head_ref, "/", repo);
	if (err != NULL)
		goto done;

	/* Ensure required files were created. */
	if (!check_meta_file_exists(worktree_path, GOT_WORKTREE_HEAD_REF))
		goto done;
	if (!check_meta_file_exists(worktree_path, GOT_WORKTREE_BASE_COMMIT))
		goto done;
	if (!check_meta_file_exists(worktree_path, GOT_WORKTREE_LOCK))
		goto done;
	if (!check_meta_file_exists(worktree_path, GOT_WORKTREE_FILE_INDEX))
		goto done;
	if (!check_meta_file_exists(worktree_path, GOT_WORKTREE_REPOSITORY))
		goto done;
	if (!check_meta_file_exists(worktree_path, GOT_WORKTREE_PATH_PREFIX))
		goto done;
	if (!check_meta_file_exists(worktree_path, GOT_WORKTREE_FORMAT))
		goto done;
	if (!check_meta_file_exists(worktree_path, GOT_WORKTREE_UUID))
		goto done;

	if (!remove_worktree(worktree_path))
		goto done;
	ok = 1;
done:
	if (head_ref)
		got_ref_close(head_ref);
	if (repo)
		got_repo_close(repo);
	return ok;
}

static int
obstruct_meta_file(char **path, const char *worktree_path, const char *name)
{
	FILE *f;
	char *s = "This file should not be here\n";
	int ret = 1;

	if (asprintf(path, "%s/%s/%s", worktree_path, GOT_WORKTREE_GOT_DIR,
	    name) == -1)
		return 0;
	f = fopen(*path, "w+");
	if (f == NULL) {
		free(*path);
		return 0;
	}
	if (fwrite(s, 1, strlen(s), f) != strlen(s)) {
		free(*path);
		ret = 0;
	}
	if (fclose(f) != 0)
		ret = 0;
	return ret;
}

static int
obstruct_meta_file_and_init(int *ok, struct got_repository *repo,
    const char *worktree_path, char *name)
{
	const struct got_error *err;
	char *path;
	int ret = 0;
	struct got_reference *head_ref = NULL;

	if (!obstruct_meta_file(&path, worktree_path, GOT_WORKTREE_FILE_INDEX))
		return 0;

	err = got_ref_open(&head_ref, repo, GOT_REF_HEAD, 0);
	if (err != NULL || head_ref == NULL)
		return 0;

	err = got_worktree_init(worktree_path, head_ref, "/", repo);
	if (err != NULL && err->code == GOT_ERR_ERRNO && errno == EEXIST) {
		(*ok)++;
		ret = 1;
	}
	unlink(path);
	free(path);
	got_ref_close(head_ref);
	return ret;
}

static int
worktree_init_exists(const char *repo_path)
{
	const struct got_error *err;
	struct got_repository *repo = NULL;
	char worktree_path[PATH_MAX];
	char *gotpath = NULL;
	int ok = 0;

	err = got_repo_open(&repo, repo_path);
	if (err != NULL || repo == NULL)
		goto done;
	strlcpy(worktree_path, "worktree-XXXXXX", sizeof(worktree_path));
	if (mkdtemp(worktree_path) == NULL)
		goto done;
	if (mkdir(worktree_path, GOT_DEFAULT_DIR_MODE) == -1 && errno != EEXIST)
		goto done;

	if (asprintf(&gotpath, "%s/%s", worktree_path, GOT_WORKTREE_GOT_DIR)
	    == -1)
		goto done;
	if (mkdir(gotpath, GOT_DEFAULT_DIR_MODE) == -1 && errno != EEXIST)
		goto done;

	/* Create files which got_worktree_init() will try to create as well. */
	if (!obstruct_meta_file_and_init(&ok, repo, worktree_path,
	    GOT_WORKTREE_HEAD_REF))
		goto done;
	if (!obstruct_meta_file_and_init(&ok, repo, worktree_path,
	    GOT_WORKTREE_BASE_COMMIT))
		goto done;
	if (!obstruct_meta_file_and_init(&ok, repo, worktree_path,
	    GOT_WORKTREE_LOCK))
		goto done;
	if (!obstruct_meta_file_and_init(&ok, repo, worktree_path,
	    GOT_WORKTREE_FILE_INDEX))
		goto done;
	if (!obstruct_meta_file_and_init(&ok, repo, worktree_path,
	    GOT_WORKTREE_REPOSITORY))
		goto done;
	if (!obstruct_meta_file_and_init(&ok, repo, worktree_path,
	    GOT_WORKTREE_PATH_PREFIX))
		goto done;
	if (!obstruct_meta_file_and_init(&ok, repo, worktree_path,
	    GOT_WORKTREE_FORMAT))
		goto done;

done:
	if (repo)
		got_repo_close(repo);
	free(gotpath);
	if (ok == 7)
		remove_worktree(worktree_path);
	return (ok == 7);
}

static void
progress_cb(void *arg, unsigned char status, const char *path)
{
}

static int
worktree_checkout(const char *repo_path)
{
	const struct got_error *err;
	struct got_repository *repo = NULL;
	struct got_reference *head_ref = NULL;
	struct got_worktree *worktree = NULL;
	char *makefile_path = NULL, *cfile_path = NULL;
	char worktree_path[PATH_MAX];
	int ok = 0;
	struct stat sb;

	err = got_repo_open(&repo, repo_path);
	if (err != NULL || repo == NULL)
		goto done;
	err = got_ref_open(&head_ref, repo, GOT_REF_HEAD, 0);
	if (err != NULL || head_ref == NULL)
		goto done;

	strlcpy(worktree_path, "worktree-XXXXXX", sizeof(worktree_path));
	if (mkdtemp(worktree_path) == NULL)
		goto done;

	err = got_worktree_init(worktree_path, head_ref, "/regress/worktree",
	    repo);
	if (err != NULL)
		goto done;

	err = got_worktree_open(&worktree, worktree_path);
	if (err != NULL)
		goto done;

	err = got_worktree_checkout_files(worktree, "", repo, progress_cb, NULL,
	    NULL, NULL);
	if (err != NULL)
		goto done;

	test_printf("checked out %s\n", worktree_path);

	/* The work tree should contain a Makefile and worktree_test.c. */
	if (asprintf(&makefile_path, "%s/Makefile", worktree_path) == -1)
		goto done;
	if (stat(makefile_path, &sb) != 0)
		goto done;
	else
		unlink(makefile_path);
	if (asprintf(&cfile_path, "%s/worktree_test.c", worktree_path) == -1)
		goto done;
	if (stat(cfile_path, &sb) != 0)
		goto done;
	else
		unlink(cfile_path);

	err = remove_worktree_base_ref(worktree, repo);
	if (err)
		goto done;
	if (!remove_worktree(worktree_path))
		goto done;

	ok = 1;
done:
	if (worktree)
		got_worktree_close(worktree);
	if (head_ref)
		got_ref_close(head_ref);
	if (repo)
		got_repo_close(repo);
	free(makefile_path);
	free(cfile_path);
	return ok;
}

#define RUN_TEST(expr, name) \
	{ test_ok = (expr);  \
	printf("test_%s %s\n", (name), test_ok ? "ok" : "failed"); \
	failure = (failure || !test_ok); }


void
usage(void)
{
	fprintf(stderr, "usage: worktree_test [-v] [REPO_PATH]\n");
}

int
main(int argc, char *argv[])
{
	int test_ok = 0, failure = 0;
	const char *repo_path;
	char *cwd = NULL;
	int ch;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec sendfd "
	    "unveil", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "v")) != -1) {
		switch (ch) {
		case 'v':
			verbose = 1;
			break;
		default:
			usage();
			return 1;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0)
		repo_path = GOT_REPO_PATH;
	else if (argc == 1)
		repo_path = argv[0];
	else {
		usage();
		return 1;
	}

	cwd = getcwd(NULL, 0);
	if (cwd == NULL)
		err(1, "getcwd");
	if (unveil(cwd, "rwc") != 0)
		err(1, "unvail");
	free(cwd);

	if (unveil("/tmp", "rwc") != 0)
		err(1, "unveil");

	if (unveil(repo_path, "rwc") != 0)
		err(1, "unveil");

	if (got_privsep_unveil_exec_helpers() != NULL)
		return 1;

	if (unveil(NULL, NULL) != 0)
		err(1, "unveil");

	RUN_TEST(worktree_init(repo_path), "init");
	RUN_TEST(worktree_init_exists(repo_path), "init exists");
	RUN_TEST(worktree_checkout(repo_path), "checkout");

	return failure ? 1 : 0;
}
