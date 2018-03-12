/*
 * Copyright (c) 2017 Martin Pieuchot <mpi@openbsd.org>
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

#include <err.h>
#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>

#include "got_error.h"
#include "got_object.h"
#include "got_refs.h"
#include "got_repository.h"
#include "got_worktree.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

struct cmd {
	const char	 *cmd_name;
	const struct got_error *(*cmd_main)(int, char *[]);
	void		(*cmd_usage)(void);
	const char	 *cmd_descr;
};

__dead void	usage(void);
__dead void	usage_checkout(void);
__dead void	usage_log(void);

const struct got_error*		cmd_checkout(int, char *[]);
const struct got_error*		cmd_log(int, char *[]);
const struct got_error*		cmd_status(int, char *[]);

struct cmd got_commands[] = {
	{ "checkout",	cmd_checkout,	usage_checkout,
	    "check out a work tree from a repository" },
	{ "log",	cmd_log,	usage_log,
	    "show repository history" },
#ifdef notyet
	{ "status",	cmd_status,	usage_status,
	    "show modification status of files" },
#endif
};

int
main(int argc, char *argv[])
{
	struct cmd *cmd;
	unsigned int i;
	int ch;
	int hflag = 0;

	setlocale(LC_ALL, "");

	while ((ch = getopt(argc, argv, "h")) != -1) {
		switch (ch) {
		case 'h':
			hflag = 1;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc <= 0)
		usage();

	for (i = 0; i < nitems(got_commands); i++) {
		const struct got_error *error;

		cmd = &got_commands[i];

		if (strncmp(cmd->cmd_name, argv[0], strlen(argv[0])))
			continue;

		if (hflag)
			got_commands[i].cmd_usage();

		error = got_commands[i].cmd_main(argc, argv);
		if (error) {
			fprintf(stderr, "%s: %s\n", getprogname(), error->msg);
			return 1;
		}

		return 0;
	}

	fprintf(stderr, "%s: unknown command '%s'\n", getprogname(), argv[0]);
	return 1;
}

__dead void
usage(void)
{
	int i;

	fprintf(stderr, "usage: %s [-h] command [arg ...]\n\n"
	    "Available commands:\n", getprogname());
	for (i = 0; i < nitems(got_commands); i++) {
		struct cmd *cmd = &got_commands[i];
		fprintf(stderr, "    %s: %s\n", cmd->cmd_name, cmd->cmd_descr);
	}
	exit(1);
}

__dead void
usage_checkout(void)
{
	fprintf(stderr, "usage: %s checkout REPO_PATH [WORKTREE_PATH]\n",
	    getprogname());
	exit(1);
}

static void
checkout_progress(void *arg, const char *path)
{
	char *worktree_path = arg;

	while (path[0] == '/')
		path++;

	printf("A  %s/%s\n", worktree_path, path);
}

const struct got_error *
cmd_checkout(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_reference *head_ref = NULL;
	struct got_worktree *worktree = NULL;
	char *repo_path = NULL;
	char *worktree_path = NULL;

	if (pledge("stdio rpath wpath cpath flock", NULL) == -1)
		err(1, "pledge");

	if (argc == 2) {
		char *cwd, *base, *dotgit;
		repo_path = argv[1];
		cwd = getcwd(NULL, 0);
		if (cwd == NULL)
			err(1, "getcwd");
		base = basename(repo_path);
		if (base == NULL)
			err(1, "basename");
		dotgit = strstr(base, ".git");
		if (dotgit)
			*dotgit = '\0';
		if (asprintf(&worktree_path, "%s/%s", cwd, base) == -1) {
			free(cwd);
			return got_error(GOT_ERR_NO_MEM);
		}
		free(cwd);
	} else if (argc == 3) {
		repo_path = argv[1];
		worktree_path = strdup(argv[2]);
		if (worktree_path == NULL)
			return got_error(GOT_ERR_NO_MEM);
	} else
		usage_checkout();

	error = got_repo_open(&repo, repo_path);
	if (error != NULL)
		goto done;
	error = got_ref_open(&head_ref, repo, GOT_REF_HEAD);
	if (error != NULL)
		goto done;

	error = got_worktree_init(worktree_path, head_ref, "/", repo);
	if (error != NULL)
		goto done;

	error = got_worktree_open(&worktree, worktree_path);
	if (error != NULL)
		goto done;

	error = got_worktree_checkout_files(worktree, head_ref, repo,
	    checkout_progress, worktree_path);
	if (error != NULL)
		goto done;

	printf("checked out %s\n", worktree_path);

done:
	free(worktree_path);
	return error;
}

static const struct got_error *
print_commit_object(struct got_object *, struct got_object_id *,
    struct got_repository *);

static const struct got_error *
print_parent_commits(struct got_commit_object *commit,
    struct got_repository *repo)
{
	struct got_parent_id *pid;
	const struct got_error *err = NULL;
	struct got_object *obj;

	SIMPLEQ_FOREACH(pid, &commit->parent_ids, entry) {
		err = got_object_open(&obj, repo, pid->id);
		if (err != NULL)
			return err;
		if (got_object_get_type(obj) != GOT_OBJ_TYPE_COMMIT)
			return got_error(GOT_ERR_OBJ_TYPE);
		err = print_commit_object(obj, pid->id, repo);
		got_object_close(obj);
	}

	return err;
}

static const struct got_error *
print_commit_object(struct got_object *obj, struct got_object_id *id,
    struct got_repository *repo)
{
	struct got_commit_object *commit;
	char *buf;
	const struct got_error *err;

	err = got_object_commit_open(&commit, repo, obj);
	if (err)
		return err;

	err = got_object_id_str(&buf, id);
	if (err)
		return err;

	printf("-----------------------------------------------\n");
	printf("commit: %s\n", buf);
	printf("Author: %s\n", commit->author);
	printf("\n%s\n", commit->logmsg);

	free(buf);

	err = print_parent_commits(commit, repo);
	got_object_commit_close(commit);
	return err;
}

__dead void
usage_log(void)
{
	fprintf(stderr, "usage: %s log [REPO_PATH]\n", getprogname());
	exit(1);
}

const struct got_error *
cmd_log(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo;
	struct got_reference *head_ref;
	struct got_object_id *id;
	struct got_object *obj;
	char *repo_path = NULL;

	if (pledge("stdio rpath wpath cpath", NULL) == -1)
		err(1, "pledge");

	if (argc == 1) {
		repo_path = getcwd(NULL, 0);
		if (repo_path == NULL)
			err(1, "getcwd");
	} else if (argc == 2)
		repo_path = argv[1];
	else
		usage_log();

	error = got_repo_open(&repo, repo_path);
	if (error != NULL)
		return error;
	error = got_ref_open(&head_ref, repo, GOT_REF_HEAD);
	if (error != NULL)
		return error;
	error = got_ref_resolve(&id, repo, head_ref);
	if (error != NULL)
		return error;

	error = got_object_open(&obj, repo, id);
	if (error != NULL)
		return error;
	if (got_object_get_type(obj) == GOT_OBJ_TYPE_COMMIT) {
		error = print_commit_object(obj, id, repo);
		if (error)
			return error;
	} else
		return got_error(GOT_ERR_OBJ_TYPE);
	got_object_close(obj);
	free(id);
	got_ref_close(head_ref);
	got_repo_close(repo);
	return NULL;
}

#ifdef notyet
const struct got_error *
cmd_status(int argc __unused, char *argv[] __unused)
{
	git_repository *repo = NULL;
	git_status_list *status;
	git_status_options statusopts;
	size_t i;

	git_libgit2_init();

	if (git_repository_open_ext(&repo, ".", 0, NULL))
		errx(1, "git_repository_open: %s", giterr_last()->message);

	if (git_repository_is_bare(repo))
		errx(1, "bar repository");

	if (git_status_init_options(&statusopts, GIT_STATUS_OPTIONS_VERSION))
		errx(1, "git_status_init_options: %s", giterr_last()->message);

	statusopts.show  = GIT_STATUS_SHOW_INDEX_AND_WORKDIR;
	statusopts.flags = GIT_STATUS_OPT_INCLUDE_UNTRACKED |
	    GIT_STATUS_OPT_RENAMES_HEAD_TO_INDEX |
	    GIT_STATUS_OPT_SORT_CASE_SENSITIVELY;

	if (git_status_list_new(&status, repo, &statusopts))
		errx(1, "git_status_list_new: %s", giterr_last()->message);

	for (i = 0; i < git_status_list_entrycount(status); i++) {
		const git_status_entry *se;

		se = git_status_byindex(status, i);
		switch (se->status) {
		case GIT_STATUS_WT_NEW:
			printf("? %s\n", se->index_to_workdir->new_file.path);
			break;
		case GIT_STATUS_WT_MODIFIED:
			printf("M %s\n", se->index_to_workdir->new_file.path);
			break;
		case GIT_STATUS_WT_DELETED:
			printf("R %s\n", se->index_to_workdir->new_file.path);
			break;
		case GIT_STATUS_WT_RENAMED:
			printf("m %s -> %s\n",
			    se->index_to_workdir->old_file.path,
			    se->index_to_workdir->new_file.path);
			break;
		case GIT_STATUS_WT_TYPECHANGE:
			printf("t %s\n", se->index_to_workdir->new_file.path);
			break;
		case GIT_STATUS_INDEX_NEW:
			printf("A %s\n", se->head_to_index->new_file.path);
			break;
		case GIT_STATUS_INDEX_MODIFIED:
			printf("M %s\n", se->head_to_index->old_file.path);
			break;
		case GIT_STATUS_INDEX_DELETED:
			printf("R %s\n", se->head_to_index->old_file.path);
			break;
		case GIT_STATUS_INDEX_RENAMED:
			printf("m %s -> %s\n",
			    se->head_to_index->old_file.path,
			    se->head_to_index->new_file.path);
			break;
		case GIT_STATUS_INDEX_TYPECHANGE:
			printf("t %s\n", se->head_to_index->old_file.path);
			break;
		case GIT_STATUS_CURRENT:
		default:
			break;
		}
	}

	git_status_list_free(status);
	git_repository_free(repo);
	git_libgit2_shutdown();

	return 0;
}
#endif
