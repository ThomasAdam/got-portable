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
#include <sys/types.h>

#include <err.h>
#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <time.h>

#include "got_error.h"
#include "got_object.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_worktree.h"
#include "got_diff.h"
#include "got_commit_graph.h"
#include "got_blame.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

struct cmd {
	const char	 *cmd_name;
	const struct got_error *(*cmd_main)(int, char *[]);
	void		(*cmd_usage)(void);
	const char	 *cmd_descr;
};

__dead static void	usage(void);
__dead static void	usage_checkout(void);
__dead static void	usage_log(void);
__dead static void	usage_diff(void);
__dead static void	usage_blame(void);

static const struct got_error*		cmd_checkout(int, char *[]);
static const struct got_error*		cmd_log(int, char *[]);
static const struct got_error*		cmd_diff(int, char *[]);
static const struct got_error*		cmd_blame(int, char *[]);
#ifdef notyet
static const struct got_error*		cmd_status(int, char *[]);
#endif

static struct cmd got_commands[] = {
	{ "checkout",	cmd_checkout,	usage_checkout,
	    "check out a new work tree from a repository" },
	{ "log",	cmd_log,	usage_log,
	    "show repository history" },
	{ "diff",	cmd_diff,	usage_diff,
	    "compare files and directories" },
	{ "blame",	cmd_blame,	usage_blame,
	    " show when lines in a file were changed" },
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

__dead static void
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

__dead static void
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

static const struct got_error *
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
	struct got_object_qid *qid;

	err = got_object_open_as_tree(&tree2, repo, commit->tree_id);
	if (err)
		return err;

	qid = SIMPLEQ_FIRST(&commit->parent_ids);
	if (qid != NULL) {
		struct got_commit_object *pcommit;

		err = got_object_open_as_commit(&pcommit, repo, qid->id);
		if (err)
			return err;

		err = got_object_open_as_tree(&tree1, repo, pcommit->tree_id);
		got_object_commit_close(pcommit);
		if (err)
			return err;
	}

	err = got_diff_tree(tree1, tree2, repo, stdout);
	if (tree1)
		got_object_tree_close(tree1);
	got_object_tree_close(tree2);
	return err;
}

static char *
get_datestr(time_t *time, char *datebuf)
{
	char *p, *s = ctime_r(time, datebuf);
	p = strchr(s, '\n');
	if (p)
		*p = '\0';
	return s;
}

static const struct got_error *
print_commit(struct got_commit_object *commit, struct got_object_id *id,
    struct got_repository *repo, int show_patch)
{
	const struct got_error *err = NULL;
	char *id_str, *datestr, *logmsg0, *logmsg, *line;
	char datebuf[26];
	time_t author_time, committer_time;

	err = got_object_id_str(&id_str, id);
	if (err)
		return err;

	author_time = mktime(&commit->tm_author);
	committer_time = mktime(&commit->tm_committer);
#if 0
	/* This would express the date in committer's timezone. */
	author_time += commit->tm_author.tm_gmtoff;
	committer_time += commit->tm_committer.tm_gmtoff;
#endif

	printf("-----------------------------------------------\n");
	printf("commit %s\n", id_str);
	free(id_str);
	datestr = get_datestr(&author_time, datebuf);
	printf("author: %s  %s UTC\n", commit->author, datestr);
	if (strcmp(commit->author, commit->committer) != 0 ||
	    author_time != committer_time) {
		datestr = get_datestr(&committer_time, datebuf);
		printf("committer: %s  %s UTC\n", commit->committer, datestr);
	}
	if (commit->nparents > 1) {
		struct got_object_qid *qid;
		int n = 1;
		SIMPLEQ_FOREACH(qid, &commit->parent_ids, entry) {
			err = got_object_id_str(&id_str, qid->id);
			if (err)
				return err;
			printf("parent %d: %s\n", n++, id_str);
			free(id_str);
		}
	}

	logmsg0 = strdup(commit->logmsg);
	if (logmsg0 == NULL)
		return got_error_from_errno();

	logmsg = logmsg0;
	do {
		line = strsep(&logmsg, "\n");
		if (line)
			printf(" %s\n", line);
	} while (line);
	free(logmsg0);

	if (show_patch) {
		err = print_patch(commit, id, repo);
		if (err == 0)
			printf("\n");
	}

	return err;
}

static const struct got_error *
print_commits(struct got_object *root_obj, struct got_object_id *root_id,
    struct got_repository *repo, char *path, int show_patch, int limit,
    int first_parent_traversal)
{
	const struct got_error *err;
	struct got_commit_graph *graph;
	int ncommits, found_obj = 0;
	int is_root_path = (strcmp(path, "/") == 0);

	err = got_commit_graph_open(&graph, root_id, first_parent_traversal,
	    repo);
	if (err)
		return err;
	err = got_commit_graph_iter_start(graph, root_id);
	if (err)
		goto done;
	do {
		struct got_commit_object *commit;
		struct got_object_id *id;

		err = got_commit_graph_iter_next(&id, graph);
		if (err) {
			if (err->code == GOT_ERR_ITER_COMPLETED) {
				err = NULL;
				break;
			}
			if (err->code != GOT_ERR_ITER_NEED_MORE)
				break;
			err = got_commit_graph_fetch_commits(&ncommits,
			    graph, 1, repo);
			if (err)
				break;
			else
				continue;
		}
		if (id == NULL)
			break;

		err = got_object_open_as_commit(&commit, repo, id);
		if (err)
			break;
		if (!is_root_path) {
			struct got_object *obj;
			struct got_object_qid *pid;
			int changed = 0;

			err = got_object_open_by_path(&obj, repo, id, path);
			if (err) {
				got_object_commit_close(commit);
				if (err->code == GOT_ERR_NO_OBJ && found_obj) {
					/*
					 * History of the path stops here
					 * on the current commit's branch.
					 * Keep logging on other branches.
					 */
					err = NULL;
					continue;
				}
				break;
			}
			found_obj = 1;

			pid = SIMPLEQ_FIRST(&commit->parent_ids);
			if (pid != NULL) {
				struct got_object *pobj;
				err = got_object_open_by_path(&pobj, repo,
				    pid->id, path);
				if (err) {
					if (err->code != GOT_ERR_NO_OBJ) {
						got_object_close(obj);
						got_object_commit_close(commit);
						break;
					}
					err = NULL;
					changed = 1;
				} else {
					struct got_object_id *id, *pid;
					id = got_object_get_id(obj);
					if (id == NULL) {
						err = got_error_from_errno();
						break;
					}
					pid = got_object_get_id(pobj);
					if (pid == NULL) {
						free(id);
						err = got_error_from_errno();
						break;
					}
					changed =
					    (got_object_id_cmp(id, pid) != 0);
					got_object_close(pobj);
					free(id);
					free(pid);
				}
			}
			got_object_close(obj);
			if (!changed) {
				got_object_commit_close(commit);
				continue;
			}
		}
		err = print_commit(commit, id, repo, show_patch);
		got_object_commit_close(commit);
		if (err || (limit && --limit == 0))
			break;
	} while (ncommits > 0);
done:
	got_commit_graph_close(graph);
	return err;
}

__dead static void
usage_log(void)
{
	fprintf(stderr, "usage: %s log [-c commit] [-f] [ -l N ] [-p] "
	    "[-r repository-path] [path]\n", getprogname());
	exit(1);
}

static const struct got_error *
cmd_log(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	struct got_object_id *id = NULL;
	struct got_object *obj = NULL;
	char *repo_path = NULL, *path = NULL, *cwd = NULL, *in_repo_path = NULL;
	char *start_commit = NULL;
	int ch;
	int show_patch = 0, limit = 0, first_parent_traversal = 0;
	const char *errstr;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "pc:l:fr:")) != -1) {
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
		case 'f':
			first_parent_traversal = 1;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				err(1, "-r option");
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0)
		path = strdup("");
	else if (argc == 1)
		path = strdup(argv[0]);
	else
		usage_log();
	if (path == NULL)
		return got_error_from_errno();

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno();
		goto done;
	}
	if (repo_path == NULL) {
		repo_path = strdup(cwd);
		if (repo_path == NULL) {
			error = got_error_from_errno();
			goto done;
		}
	}

	error = got_repo_open(&repo, repo_path);
	if (error != NULL)
		goto done;

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
		struct got_reference *ref;
		error = got_ref_open(&ref, repo, start_commit);
		if (error == NULL) {
			error = got_ref_resolve(&id, repo, ref);
			got_ref_close(ref);
			if (error != NULL)
				return error;
			error = got_object_open(&obj, repo, id);
			if (error != NULL)
				return error;
		}
		if (obj == NULL) {
			error = got_object_open_by_id_str(&obj, repo,
			    start_commit);
			if (error != NULL)
				return error;
			id = got_object_get_id(obj);
			if (id == NULL)
				error = got_error_from_errno();
		}
	}
	if (error != NULL)
		goto done;
	if (got_object_get_type(obj) != GOT_OBJ_TYPE_COMMIT) {
		error = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	error = got_repo_map_path(&in_repo_path, repo, path);
	if (error != NULL)
		goto done;
	if (in_repo_path) {
		free(path);
		path = in_repo_path;
	}

	error = print_commits(obj, id, repo, path, show_patch,
	    limit, first_parent_traversal);
done:
	free(path);
	free(repo_path);
	free(cwd);
	if (obj)
		got_object_close(obj);
	free(id);
	if (repo)
		got_repo_close(repo);
	return error;
}

__dead static void
usage_diff(void)
{
	fprintf(stderr, "usage: %s diff [repository-path] object1 object2\n",
	    getprogname());
	exit(1);
}

static const struct got_error *
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
		error = got_diff_objects_as_blobs(obj1, obj2, repo, stdout);
		break;
	case GOT_OBJ_TYPE_TREE:
		error = got_diff_objects_as_trees(obj1, obj2, repo, stdout);
		break;
	case GOT_OBJ_TYPE_COMMIT:
		error = got_diff_objects_as_commits(obj1, obj2, repo, stdout);
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

__dead static void
usage_blame(void)
{
	fprintf(stderr, "usage: %s blame [-c commit] [repository-path] path\n",
	    getprogname());
	exit(1);
}

static const struct got_error *
cmd_blame(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	char *repo_path = NULL;
	char *path = NULL;
	struct got_object_id *commit_id = NULL;
	char *commit_id_str = NULL;
	int ch;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "c:")) != -1) {
		switch (ch) {
		case 'c':
			commit_id_str = optarg;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0) {
		usage_blame();
	} else if (argc == 1) {
		repo_path = getcwd(NULL, 0);
		if (repo_path == NULL)
			return got_error_from_errno();
		path = argv[0];
	} else if (argc == 2) {
		repo_path = realpath(argv[0], NULL);
		if (repo_path == NULL)
			return got_error_from_errno();
		path = argv[1];
	} else
		usage_blame();

	error = got_repo_open(&repo, repo_path);
	free(repo_path);
	if (error != NULL)
		goto done;

	if (commit_id_str == NULL) {
		struct got_reference *head_ref;
		error = got_ref_open(&head_ref, repo, GOT_REF_HEAD);
		if (error != NULL)
			return error;
		error = got_ref_resolve(&commit_id, repo, head_ref);
		got_ref_close(head_ref);
		if (error != NULL)
			return error;
	} else {
		struct got_object *obj;
		error = got_object_open_by_id_str(&obj, repo, commit_id_str);
		if (error != NULL)
			return error;
		commit_id = got_object_get_id(obj);
		if (commit_id == NULL)
			error = got_error_from_errno();
		got_object_close(obj);
	}

	error = got_blame(path, commit_id, repo, stdout);
done:
	free(commit_id);
	if (repo)
		got_repo_close(repo);
	return error;
}

#ifdef notyet
static const struct got_error *
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
