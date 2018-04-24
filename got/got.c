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
#include <sys/limits.h>

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
#include "got_reference.h"
#include "got_repository.h"
#include "got_worktree.h"
#include "got_diff.h"

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
__dead void	usage_diff(void);

const struct got_error*		cmd_checkout(int, char *[]);
const struct got_error*		cmd_log(int, char *[]);
const struct got_error*		cmd_diff(int, char *[]);
const struct got_error*		cmd_status(int, char *[]);

struct cmd got_commands[] = {
	{ "checkout",	cmd_checkout,	usage_checkout,
	    "check out a new work tree from a repository" },
	{ "log",	cmd_log,	usage_log,
	    "show repository history" },
	{ "diff",	cmd_diff,	usage_diff,
	    "compare files and directories" },
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
	optind = 0;

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
	fprintf(stderr, "usage: %s checkout [-p prefix] repository-path "
	    "[worktree-path]\n", getprogname());
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
	const char *path_prefix = "";
	int ch;

	while ((ch = getopt(argc, argv, "p:")) != -1) {
		switch (ch) {
		case 'p':
			path_prefix = optarg;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc", NULL) == -1)
		err(1, "pledge");
#endif
	if (argc == 1) {
		char *cwd, *base, *dotgit;
		repo_path = realpath(argv[0], NULL);
		if (repo_path == NULL)
			return got_error_from_errno();
		cwd = getcwd(NULL, 0);
		if (cwd == NULL) {
			error = got_error_from_errno();
			goto done;
		}
		if (path_prefix[0])
			base = basename(path_prefix);
		else
			base = basename(repo_path);
		if (base == NULL) {
			error = got_error_from_errno();
			goto done;
		}
		dotgit = strstr(base, ".git");
		if (dotgit)
			*dotgit = '\0';
		if (asprintf(&worktree_path, "%s/%s", cwd, base) == -1) {
			error = got_error_from_errno();
			free(cwd);
			goto done;
		}
		free(cwd);
	} else if (argc == 2) {
		repo_path = realpath(argv[0], NULL);
		if (repo_path == NULL) {
			error = got_error_from_errno();
			goto done;
		}
		worktree_path = realpath(argv[1], NULL);
		if (worktree_path == NULL) {
			error = got_error_from_errno();
			goto done;
		}
	} else
		usage_checkout();

	error = got_repo_open(&repo, repo_path);
	if (error != NULL)
		goto done;
	error = got_ref_open(&head_ref, repo, GOT_REF_HEAD);
	if (error != NULL)
		goto done;

	error = got_worktree_init(worktree_path, head_ref, path_prefix, repo);
	if (error != NULL)
		goto done;

	error = got_worktree_open(&worktree, worktree_path);
	if (error != NULL)
		goto done;

	error = got_worktree_checkout_files(worktree, head_ref, repo,
	    checkout_progress, worktree_path);
	if (error != NULL)
		goto done;

	printf("Checked out %s\n", worktree_path);
	printf("Now shut up and hack\n");

done:
	free(repo_path);
	free(worktree_path);
	return error;
}

static const struct got_error *
print_patch(struct got_commit_object *commit, struct got_object_id *id,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_tree_object *tree1 = NULL, *tree2;
	struct got_object *obj;
	struct got_parent_id *pid;

	err = got_object_open(&obj, repo, commit->tree_id);
	if (err)
		return err;

	err = got_object_tree_open(&tree2, repo, obj);
	got_object_close(obj);
	if (err)
		return err;

	pid = SIMPLEQ_FIRST(&commit->parent_ids);
	if (pid != NULL) {
		struct got_commit_object *pcommit;

		err = got_object_open(&obj, repo, pid->id);
		if (err)
			return err;

		err = got_object_commit_open(&pcommit, repo, obj);
		got_object_close(obj);
		if (err)
			return err;

		err = got_object_open(&obj, repo, pcommit->tree_id);
		got_object_commit_close(pcommit);
		if (err)
			return err;
		err = got_object_tree_open(&tree1, repo, obj);
		got_object_close(obj);
		if (err)
			return err;
	}

	err = got_diff_tree(tree1, tree2, repo, stdout);
	if (tree1)
		got_object_tree_close(tree1);
	got_object_tree_close(tree2);
	return err;
}

static const struct got_error *
print_commit(struct got_commit_object *commit, struct got_object_id *id,
    struct got_repository *repo, int show_patch)
{
	const struct got_error *err = NULL;
	char *buf;

	err = got_object_id_str(&buf, id);
	if (err)
		return err;

	printf("-----------------------------------------------\n");
	printf("commit %s\n", buf);
	printf("author: %s\n", commit->author);
	if (strcmp(commit->author, commit->committer) != 0)
		printf("committer: %s\n", commit->committer);
	printf("\n%s\n", commit->logmsg);

	if (show_patch) {
		err = print_patch(commit, id, repo);
		if (err == 0)
			printf("\n");
	}

	free(buf);
	return err;
}

struct commit_queue_entry {
	TAILQ_ENTRY(commit_queue_entry) entry;
	struct got_object_id *id;
	struct got_commit_object *commit;
};

static const struct got_error *
print_commits(struct got_object *root_obj, struct got_object_id *root_id,
    struct got_repository *repo, int show_patch, int limit)
{
	const struct got_error *err;
	struct got_commit_object *root_commit;
	TAILQ_HEAD(, commit_queue_entry) commits;
	struct commit_queue_entry *entry;

	TAILQ_INIT(&commits);

	err = got_object_commit_open(&root_commit, repo, root_obj);
	if (err)
		return err;

	entry = calloc(1, sizeof(*entry));
	if (entry == NULL)
		return got_error_from_errno();
	entry->id = got_object_id_dup(root_id);
	if (entry->id == NULL) {
		err = got_error_from_errno();
		free(entry);
		return err;
	}
	entry->commit = root_commit;
	TAILQ_INSERT_HEAD(&commits, entry, entry);

	while (!TAILQ_EMPTY(&commits)) {
		struct got_parent_id *pid;
		struct got_object *obj;
		struct got_commit_object *pcommit;
		struct commit_queue_entry *pentry;

		entry = TAILQ_FIRST(&commits);

		err = print_commit(entry->commit, entry->id, repo, show_patch);
		if (err)
			break;

		if (limit && --limit == 0)
			break;

		if (entry->commit->nparents == 0)
			break;

		/* Follow the first parent (TODO: handle merge commits). */
		pid = SIMPLEQ_FIRST(&entry->commit->parent_ids);
		err = got_object_open(&obj, repo, pid->id);
		if (err)
			break;
		if (got_object_get_type(obj) != GOT_OBJ_TYPE_COMMIT) {
			err = got_error(GOT_ERR_OBJ_TYPE);
			break;
		}

		err = got_object_commit_open(&pcommit, repo, obj);
		got_object_close(obj);
		if (err)
			break;

		pentry = calloc(1, sizeof(*pentry));
		if (pentry == NULL) {
			err = got_error_from_errno();
			got_object_commit_close(pcommit);
			break;
		}
		pentry->id = got_object_id_dup(pid->id);
		if (pentry->id == NULL) {
			err = got_error_from_errno();
			got_object_commit_close(pcommit);
			break;
		}
		pentry->commit = pcommit;
		TAILQ_INSERT_TAIL(&commits, pentry, entry);

		TAILQ_REMOVE(&commits, entry, entry);
		got_object_commit_close(entry->commit);
		free(entry->id);
		free(entry);
	}

	while (!TAILQ_EMPTY(&commits)) {
		entry = TAILQ_FIRST(&commits);
		TAILQ_REMOVE(&commits, entry, entry);
		got_object_commit_close(entry->commit);
		free(entry->id);
		free(entry);
	}

	return err;
}

__dead void
usage_log(void)
{
	fprintf(stderr, "usage: %s log [-p] [-c commit] [ -l N ] "
	    "[repository-path]\n", getprogname());
	exit(1);
}

const struct got_error *
cmd_log(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo;
	struct got_object_id *id = NULL;
	struct got_object *obj;
	char *repo_path = NULL;
	char *start_commit = NULL;
	int ch;
	int show_patch = 0, limit = 0;
	const char *errstr;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "pc:l:")) != -1) {
		switch (ch) {
		case 'p':
			show_patch = 1;
			break;
		case 'c':
			start_commit = optarg;
			break;
		case 'l':
			limit = strtonum(optarg, 1, INT_MAX, &errstr);
			if (errstr != NULL)
				err(1, "-l option %s", errstr);
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0) {
		repo_path = getcwd(NULL, 0);
		if (repo_path == NULL)
			return got_error_from_errno();
	} else if (argc == 1) {
		repo_path = realpath(argv[0], NULL);
		if (repo_path == NULL)
			return got_error_from_errno();
	} else
		usage_log();

	error = got_repo_open(&repo, repo_path);
	free(repo_path);
	if (error != NULL)
		return error;

	if (start_commit == NULL) {
		struct got_reference *head_ref;
		error = got_ref_open(&head_ref, repo, GOT_REF_HEAD);
		if (error != NULL)
			return error;
		error = got_ref_resolve(&id, repo, head_ref);
		got_ref_close(head_ref);
		if (error != NULL)
			return error;
		error = got_object_open(&obj, repo, id);
	} else {
		error = got_object_open_by_id_str(&obj, repo, start_commit);
		if (error == NULL) {
			id = got_object_get_id(obj);
			if (id == NULL)
				error = got_error_from_errno();
		}
	}
	if (error != NULL)
		return error;
	if (got_object_get_type(obj) == GOT_OBJ_TYPE_COMMIT)
		error = print_commits(obj, id, repo, show_patch, limit);
	else
		error = got_error(GOT_ERR_OBJ_TYPE);
	got_object_close(obj);
	free(id);
	got_repo_close(repo);
	return error;
}

static const struct got_error *
diff_blobs(struct got_object *obj1, struct got_object *obj2,
    struct got_repository *repo)
{
	const struct got_error *err;
	struct got_blob_object *blob1 = NULL, *blob2 = NULL;

	err = got_object_blob_open(&blob1, repo, obj1, 8192);
	if (err)
		goto done;
	err = got_object_blob_open(&blob2, repo, obj2, 81992);
	if (err)
		goto done;

	err = got_diff_blob(blob1, blob2, NULL, NULL, stdout);
done:
	if (blob1)
		got_object_blob_close(blob1);
	if (blob2)
		got_object_blob_close(blob2);
	return err;
}

static const struct got_error *
diff_trees(struct got_object *obj1, struct got_object *obj2,
    struct got_repository *repo)
{
	const struct got_error *err;
	struct got_tree_object *tree1 = NULL, *tree2 = NULL;

	err = got_object_tree_open(&tree1, repo, obj1);
	if (err)
		goto done;
	err = got_object_tree_open(&tree2, repo, obj2);
	if (err)
		goto done;

	err = got_diff_tree(tree1, tree2, repo, stdout);
done:
	if (tree1)
		got_object_tree_close(tree1);
	if (tree2)
		got_object_tree_close(tree2);
	return err;
}

static const struct got_error *
diff_commits(struct got_object *obj1, struct got_object *obj2,
    struct got_repository *repo)
{
	const struct got_error *err;
	struct got_commit_object *commit1 = NULL, *commit2 = NULL;
	struct got_object *tree_obj1  = NULL, *tree_obj2 = NULL;

	err = got_object_commit_open(&commit1, repo, obj1);
	if (err)
		goto done;
	err = got_object_commit_open(&commit2, repo, obj2);
	if (err)
		goto done;

	err = got_object_open(&tree_obj1, repo, commit1->tree_id);
	if (err)
		goto done;
	err = got_object_open(&tree_obj2, repo, commit2->tree_id);
	if (err)
		goto done;

	err = diff_trees(tree_obj1, tree_obj2, repo);
done:
	if (tree_obj1)
		got_object_close(tree_obj1);
	if (tree_obj2)
		got_object_close(tree_obj2);
	if (commit1)
		got_object_commit_close(commit1);
	if (commit2)
		got_object_commit_close(commit2);
	return err;

}

__dead void
usage_diff(void)
{
	fprintf(stderr, "usage: %s diff [repository-path] object1 object2\n",
	    getprogname());
	exit(1);
}

const struct got_error *
cmd_diff(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	struct got_object_id *id1 = NULL, *id2 = NULL;
	struct got_object *obj1 = NULL, *obj2 = NULL;
	char *repo_path = NULL;
	char *obj_id_str1 = NULL, *obj_id_str2 = NULL;
	int ch;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0) {
		usage_diff(); /* TODO show local worktree changes */
	} else if (argc == 2) {
		repo_path = getcwd(NULL, 0);
		if (repo_path == NULL)
			return got_error_from_errno();
		obj_id_str1 = argv[0];
		obj_id_str2 = argv[1];
	} else if (argc == 3) {
		repo_path = realpath(argv[0], NULL);
		if (repo_path == NULL)
			return got_error_from_errno();
		obj_id_str1 = argv[1];
		obj_id_str2 = argv[2];
	} else
		usage_diff();

	error = got_repo_open(&repo, repo_path);
	free(repo_path);
	if (error != NULL)
		goto done;

	error = got_object_open_by_id_str(&obj1, repo, obj_id_str1);
	if (error == NULL) {
		id1 = got_object_get_id(obj1);
		if (id1 == NULL)
			error = got_error_from_errno();
	}
	if (error != NULL)
		goto done;

	error = got_object_open_by_id_str(&obj2, repo, obj_id_str2);
	if (error == NULL) {
		id2 = got_object_get_id(obj2);
		if (id2 == NULL)
			error = got_error_from_errno();
	}
	if (error != NULL)
		goto done;

	if (got_object_get_type(obj1) != got_object_get_type(obj2)) {
		error = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	switch (got_object_get_type(obj1)) {
	case GOT_OBJ_TYPE_BLOB:
		error = diff_blobs(obj1, obj2, repo);
		break;
	case GOT_OBJ_TYPE_TREE:
		error = diff_trees(obj1, obj2, repo);
		break;
	case GOT_OBJ_TYPE_COMMIT:
		error = diff_commits(obj1, obj2, repo);
		break;
	default:
		error = got_error(GOT_ERR_OBJ_TYPE);
	}

done:
	if (obj1)
		got_object_close(obj1);
	if (obj2)
		got_object_close(obj2);
	if (id1)
		free(id1);
	if (id2)
		free(id2);
	if (repo)
		got_repo_close(repo);
	return error;
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
