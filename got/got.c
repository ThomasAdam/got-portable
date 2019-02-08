/*
 * Copyright (c) 2017 Martin Pieuchot <mpi@openbsd.org>
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

#include <sys/queue.h>
#include <sys/limits.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <locale.h>
#include <signal.h>
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
#include "got_privsep.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

static volatile sig_atomic_t sigint_received;
static volatile sig_atomic_t sigpipe_received;

static void
catch_sigint(int signo)
{
	sigint_received = 1;
}

static void
catch_sigpipe(int signo)
{
	sigpipe_received = 1;
}


struct cmd {
	const char	 *cmd_name;
	const struct got_error *(*cmd_main)(int, char *[]);
	void		(*cmd_usage)(void);
	const char	 *cmd_descr;
};

__dead static void	usage(void);
__dead static void	usage_checkout(void);
__dead static void	usage_update(void);
__dead static void	usage_log(void);
__dead static void	usage_diff(void);
__dead static void	usage_blame(void);
__dead static void	usage_tree(void);
__dead static void	usage_status(void);

static const struct got_error*		cmd_checkout(int, char *[]);
static const struct got_error*		cmd_update(int, char *[]);
static const struct got_error*		cmd_log(int, char *[]);
static const struct got_error*		cmd_diff(int, char *[]);
static const struct got_error*		cmd_blame(int, char *[]);
static const struct got_error*		cmd_tree(int, char *[]);
static const struct got_error*		cmd_status(int, char *[]);

static struct cmd got_commands[] = {
	{ "checkout",	cmd_checkout,	usage_checkout,
	    "check out a new work tree from a repository" },
	{ "update",	cmd_update,	usage_update,
	    "update a work tree to a different commit" },
	{ "log",	cmd_log,	usage_log,
	    "show repository history" },
	{ "diff",	cmd_diff,	usage_diff,
	    "compare files and directories" },
	{ "blame",	cmd_blame,	usage_blame,
	    " show when lines in a file were changed" },
	{ "tree",	cmd_tree,	usage_tree,
	    " list files and directories in repository" },
	{ "status",	cmd_status,	usage_status,
	    "show modification status of files" },
};

int
main(int argc, char *argv[])
{
	struct cmd *cmd;
	unsigned int i;
	int ch;
	int hflag = 0;

	setlocale(LC_CTYPE, "");

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

	signal(SIGINT, catch_sigint);
	signal(SIGPIPE, catch_sigpipe);

	for (i = 0; i < nitems(got_commands); i++) {
		const struct got_error *error;

		cmd = &got_commands[i];

		if (strncmp(cmd->cmd_name, argv[0], strlen(argv[0])))
			continue;

		if (hflag)
			got_commands[i].cmd_usage();

		error = got_commands[i].cmd_main(argc, argv);
		if (error && !(sigint_received || sigpipe_received)) {
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

static const struct got_error *
apply_unveil(const char *repo_path, const char *worktree_path)
{
	const struct got_error *error;

	if (repo_path && unveil(repo_path, "r") != 0)
		return got_error_from_errno();

	if (worktree_path && unveil(worktree_path, "rwc") != 0)
		return got_error_from_errno();

	if (unveil("/tmp", "rwc") != 0)
		return got_error_from_errno();

	error = got_privsep_unveil_exec_helpers();
	if (error != NULL)
		return error;

	if (unveil(NULL, NULL) != 0)
		return got_error_from_errno();

	return NULL;
}

__dead static void
usage_checkout(void)
{
	fprintf(stderr, "usage: %s checkout [-p prefix] repository-path "
	    "[worktree-path]\n", getprogname());
	exit(1);
}

static void
checkout_progress(void *arg, unsigned char status, const char *path)
{
	char *worktree_path = arg;

	while (path[0] == '/')
		path++;

	printf("%c  %s/%s\n", status, worktree_path, path);
}

static const struct got_error *
check_cancelled(void *arg)
{
	if (sigint_received || sigpipe_received)
		return got_error(GOT_ERR_CANCELLED);
	return NULL;
}

static const struct got_error *
check_ancestry(struct got_worktree *worktree, struct got_object_id *commit_id,
    struct got_repository *repo)
{
	const struct got_error *err;
	struct got_reference *head_ref = NULL;
	struct got_object_id *head_commit_id = NULL;
	struct got_commit_graph *graph = NULL;

	head_ref = got_worktree_get_head_ref(worktree);
	if (head_ref == NULL)
		return got_error_from_errno();

	/* TODO: Check the reflog. The head ref may have been rebased. */
	err = got_ref_resolve(&head_commit_id, repo, head_ref);
	if (err)
		goto done;

	err = got_commit_graph_open(&graph, head_commit_id, "/", 1, repo);
	if (err)
		goto done;

	err = got_commit_graph_iter_start(graph, head_commit_id, repo);
	if (err)
		goto done;
	while (1) {
		struct got_object_id *id;

		if (sigint_received || sigpipe_received)
			break;

		err = got_commit_graph_iter_next(&id, graph);
		if (err) {
			if (err->code == GOT_ERR_ITER_COMPLETED) {
				err = got_error(GOT_ERR_ANCESTRY);
				break;
			}
			if (err->code != GOT_ERR_ITER_NEED_MORE)
				break;
			err = got_commit_graph_fetch_commits(graph, 1, repo);
			if (err)
				break;
			else
				continue;
		}
		if (id == NULL)
			break;
		if (got_object_id_cmp(id, commit_id) == 0)
			break;
	}
done:
	if (head_ref)
		got_ref_close(head_ref);
	if (graph)
		got_commit_graph_close(graph);
	return err;
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
	char *commit_id_str = NULL;
	int ch, same_path_prefix;

	while ((ch = getopt(argc, argv, "c:p:")) != -1) {
		switch (ch) {
		case 'c':
			commit_id_str = strdup(optarg);
			if (commit_id_str == NULL)
				return got_error_from_errno();
			break;
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
	if (pledge("stdio rpath wpath cpath flock proc exec sendfd unveil",
	    NULL) == -1)
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

	error = apply_unveil(repo_path, worktree_path);
	if (error)
		goto done;

	error = got_repo_open(&repo, repo_path);
	if (error != NULL)
		goto done;

	error = got_ref_open(&head_ref, repo, GOT_REF_HEAD);
	if (error != NULL)
		goto done;

	error = got_worktree_init(worktree_path, head_ref, path_prefix, repo);
	if (error != NULL && !(error->code == GOT_ERR_ERRNO && errno == EEXIST))
		goto done;

	error = got_worktree_open(&worktree, worktree_path);
	if (error != NULL)
		goto done;

	error = got_worktree_match_path_prefix(&same_path_prefix, worktree,
	    path_prefix);
	if (error != NULL)
		goto done;
	if (!same_path_prefix) {
		error = got_error(GOT_ERR_PATH_PREFIX);
		goto done;
	}

	if (commit_id_str) {
		struct got_object_id *commit_id;
		error = got_object_resolve_id_str(&commit_id, repo,
		    commit_id_str);
		if (error != NULL)
			goto done;
		error = check_ancestry(worktree, commit_id, repo);
		if (error != NULL) {
			free(commit_id);
			goto done;
		}
		error = got_worktree_set_base_commit_id(worktree, repo,
		    commit_id);
		free(commit_id);
		if (error)
			goto done;
	}

	error = got_worktree_checkout_files(worktree, repo,
	    checkout_progress, worktree_path, check_cancelled, NULL);
	if (error != NULL)
		goto done;

	printf("Now shut up and hack\n");

done:
	free(commit_id_str);
	free(repo_path);
	free(worktree_path);
	return error;
}

__dead static void
usage_update(void)
{
	fprintf(stderr, "usage: %s update [-c commit] [worktree-path]\n",
	    getprogname());
	exit(1);
}

static void
update_progress(void *arg, unsigned char status, const char *path)
{
	int *did_something = arg;

	if (status == GOT_STATUS_EXISTS)
		return;

	*did_something = 1;
	while (path[0] == '/')
		path++;
	printf("%c  %s\n", status, path);
}

static const struct got_error *
cmd_update(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *worktree_path = NULL;
	struct got_object_id *commit_id = NULL;
	char *commit_id_str = NULL;
	int ch, did_something = 0;

	while ((ch = getopt(argc, argv, "c:")) != -1) {
		switch (ch) {
		case 'c':
			commit_id_str = strdup(optarg);
			if (commit_id_str == NULL)
				return got_error_from_errno();
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif
	if (argc == 0) {
		worktree_path = getcwd(NULL, 0);
		if (worktree_path == NULL) {
			error = got_error_from_errno();
			goto done;
		}
	} else if (argc == 1) {
		worktree_path = realpath(argv[0], NULL);
		if (worktree_path == NULL) {
			error = got_error_from_errno();
			goto done;
		}
	} else
		usage_update();

	error = got_worktree_open(&worktree, worktree_path);
	if (error != NULL)
		goto done;

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree));
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo),
	    got_worktree_get_root_path(worktree));
	if (error)
		goto done;

	if (commit_id_str == NULL) {
		struct got_reference *head_ref;
		error = got_ref_open(&head_ref, repo, GOT_REF_HEAD);
		if (error != NULL)
			goto done;
		error = got_ref_resolve(&commit_id, repo, head_ref);
		if (error != NULL)
			goto done;
		error = got_object_id_str(&commit_id_str, commit_id);
		if (error != NULL)
			goto done;
	} else {
		error = got_object_resolve_id_str(&commit_id, repo,
		    commit_id_str);
		if (error != NULL)
			goto done;
	}

	error = check_ancestry(worktree, commit_id, repo);
	if (error != NULL)
		goto done;

	if (got_object_id_cmp(got_worktree_get_base_commit_id(worktree),
	    commit_id) != 0) {
		error = got_worktree_set_base_commit_id(worktree, repo,
		    commit_id);
		if (error)
			goto done;
	}

	error = got_worktree_checkout_files(worktree, repo,
	    update_progress, &did_something, check_cancelled, NULL);
	if (error != NULL)
		goto done;

	if (did_something)
		printf("Updated to commit %s\n", commit_id_str);
	else
		printf("Already up-to-date\n");
done:
	free(worktree_path);
	free(commit_id);
	free(commit_id_str);
	return error;
}

static const struct got_error *
print_patch(struct got_commit_object *commit, struct got_object_id *id,
    int diff_context, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_tree_object *tree1 = NULL, *tree2;
	struct got_object_qid *qid;
	char *id_str1 = NULL, *id_str2;

	err = got_object_open_as_tree(&tree2, repo,
	    got_object_commit_get_tree_id(commit));
	if (err)
		return err;

	qid = SIMPLEQ_FIRST(got_object_commit_get_parent_ids(commit));
	if (qid != NULL) {
		struct got_commit_object *pcommit;

		err = got_object_open_as_commit(&pcommit, repo, qid->id);
		if (err)
			return err;

		err = got_object_open_as_tree(&tree1, repo,
		    got_object_commit_get_tree_id(pcommit));
		got_object_commit_close(pcommit);
		if (err)
			return err;

		err = got_object_id_str(&id_str1, qid->id);
		if (err)
			return err;
	}

	err = got_object_id_str(&id_str2, id);
	if (err)
		goto done;

	printf("diff %s %s\n", id_str1 ? id_str1 : "/dev/null", id_str2);
	err = got_diff_tree(tree1, tree2, "", "", diff_context, repo, stdout);
done:
	if (tree1)
		got_object_tree_close(tree1);
	got_object_tree_close(tree2);
	free(id_str1);
	free(id_str2);
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
    struct got_repository *repo, int show_patch, int diff_context,
    struct got_reflist_head *refs)
{
	const struct got_error *err = NULL;
	char *id_str, *datestr, *logmsg0, *logmsg, *line;
	char datebuf[26];
	time_t committer_time;
	const char *author, *committer;
	char *refs_str = NULL;
	struct got_reflist_entry *re;

	SIMPLEQ_FOREACH(re, refs, entry) {
		char *s;
		const char *name;
		if (got_object_id_cmp(re->id, id) != 0)
			continue;
		name = got_ref_get_name(re->ref);
		if (strcmp(name, GOT_REF_HEAD) == 0)
			continue;
		if (strncmp(name, "refs/", 5) == 0)
			name += 5;
		if (strncmp(name, "heads/", 6) == 0)
			name += 6;
		if (strncmp(name, "remotes/", 8) == 0)
			name += 8;
		s = refs_str;
		if (asprintf(&refs_str, "%s%s%s", s ? s : "", s ? ", " : "",
		    name) == -1) {
			err = got_error_from_errno();
			free(s);
			break;
		}
		free(s);
	}
	err = got_object_id_str(&id_str, id);
	if (err)
		return err;

	printf("-----------------------------------------------\n");
	printf("commit %s%s%s%s\n", id_str, refs_str ? " (" : "",
	    refs_str ? refs_str : "", refs_str ? ")" : "");
	free(id_str);
	printf("from: %s\n", got_object_commit_get_author(commit));
	committer_time = got_object_commit_get_committer_time(commit);
	datestr = get_datestr(&committer_time, datebuf);
	printf("date: %s UTC\n", datestr);
	author = got_object_commit_get_author(commit);
	committer = got_object_commit_get_committer(commit);
	if (strcmp(author, committer) != 0)
		printf("via: %s\n", committer);
	if (got_object_commit_get_nparents(commit) > 1) {
		const struct got_object_id_queue *parent_ids;
		struct got_object_qid *qid;
		int n = 1;
		parent_ids = got_object_commit_get_parent_ids(commit);
		SIMPLEQ_FOREACH(qid, parent_ids, entry) {
			err = got_object_id_str(&id_str, qid->id);
			if (err)
				return err;
			printf("parent %d: %s\n", n++, id_str);
			free(id_str);
		}
	}

	logmsg0 = strdup(got_object_commit_get_logmsg(commit));
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
		err = print_patch(commit, id, diff_context, repo);
		if (err == 0)
			printf("\n");
	}

	fflush(stdout);
	return err;
}

static const struct got_error *
print_commits(struct got_object_id *root_id, struct got_repository *repo,
    char *path, int show_patch, int diff_context, int limit,
    int first_parent_traversal, struct got_reflist_head *refs)
{
	const struct got_error *err;
	struct got_commit_graph *graph;

	err = got_commit_graph_open(&graph, root_id, path,
	    first_parent_traversal, repo);
	if (err)
		return err;
	err = got_commit_graph_iter_start(graph, root_id, repo);
	if (err)
		goto done;
	while (1) {
		struct got_commit_object *commit;
		struct got_object_id *id;

		if (sigint_received || sigpipe_received)
			break;

		err = got_commit_graph_iter_next(&id, graph);
		if (err) {
			if (err->code == GOT_ERR_ITER_COMPLETED) {
				err = NULL;
				break;
			}
			if (err->code != GOT_ERR_ITER_NEED_MORE)
				break;
			err = got_commit_graph_fetch_commits(graph, 1, repo);
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
		err = print_commit(commit, id, repo, show_patch, diff_context,
		    refs);
		got_object_commit_close(commit);
		if (err || (limit && --limit == 0))
			break;
	}
done:
	got_commit_graph_close(graph);
	return err;
}

__dead static void
usage_log(void)
{
	fprintf(stderr, "usage: %s log [-c commit] [-C number] [-f] [ -l N ] [-p] "
	    "[-r repository-path] [path]\n", getprogname());
	exit(1);
}

static const struct got_error *
cmd_log(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	struct got_commit_object *commit = NULL;
	struct got_object_id *id = NULL;
	char *repo_path = NULL, *path = NULL, *cwd = NULL, *in_repo_path = NULL;
	char *start_commit = NULL;
	int diff_context = 3, ch;
	int show_patch = 0, limit = 0, first_parent_traversal = 0;
	const char *errstr;
	struct got_reflist_head refs;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc exec sendfd unveil",
	    NULL)
	    == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "pc:C:l:fr:")) != -1) {
		switch (ch) {
		case 'p':
			show_patch = 1;
			break;
		case 'c':
			start_commit = optarg;
			break;
		case 'C':
			diff_context = strtonum(optarg, 0, GOT_DIFF_MAX_CONTEXT,
			    &errstr);
			if (errstr != NULL)
				err(1, "-C option %s", errstr);
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

	error = got_worktree_open(&worktree, cwd);
	if (error && error->code != GOT_ERR_NOT_WORKTREE)
		goto done;
	error = NULL;

	repo_path = worktree ?
	    strdup(got_worktree_get_repo_path(worktree)) : strdup(cwd);
	if (repo_path == NULL) {
		error = got_error_from_errno();
		goto done;
	}

	error = apply_unveil(repo_path, NULL);
	if (error)
		goto done;

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
		error = got_object_open_as_commit(&commit, repo, id);
	} else {
		struct got_reference *ref;
		error = got_ref_open(&ref, repo, start_commit);
		if (error == NULL) {
			int obj_type;
			error = got_ref_resolve(&id, repo, ref);
			got_ref_close(ref);
			if (error != NULL)
				goto done;
			error = got_object_get_type(&obj_type, repo, id);
			if (error != NULL)
				goto done;
			if (obj_type == GOT_OBJ_TYPE_TAG) {
				struct got_tag_object *tag;
				error = got_object_open_as_tag(&tag, repo, id);
				if (error != NULL)
					goto done;
				if (got_object_tag_get_object_type(tag) !=
				    GOT_OBJ_TYPE_COMMIT) {
					got_object_tag_close(tag);
					error = got_error(GOT_ERR_OBJ_TYPE);
					goto done;
				}
				free(id);
				id = got_object_id_dup(
				    got_object_tag_get_object_id(tag));
				if (id == NULL)
					error = got_error_from_errno();
				got_object_tag_close(tag);
				if (error)
					goto done;
			} else if (obj_type != GOT_OBJ_TYPE_COMMIT) {
				error = got_error(GOT_ERR_OBJ_TYPE);
				goto done;
			}
			error = got_object_open_as_commit(&commit, repo, id);
			if (error != NULL)
				goto done;
		}
		if (commit == NULL) {
			error = got_object_resolve_id_str(&id, repo,
			    start_commit);
			if (error != NULL)
				return error;
		}
	}
	if (error != NULL)
		goto done;

	error = got_repo_map_path(&in_repo_path, repo, path, 1);
	if (error != NULL)
		goto done;
	if (in_repo_path) {
		free(path);
		path = in_repo_path;
	}

	SIMPLEQ_INIT(&refs);
	error = got_ref_list(&refs, repo);
	if (error)
		goto done;

	error = print_commits(id, repo, path, show_patch,
	    diff_context, limit, first_parent_traversal, &refs);
done:
	free(path);
	free(repo_path);
	free(cwd);
	free(id);
	if (worktree)
		got_worktree_close(worktree);
	if (repo) {
		const struct got_error *repo_error;
		repo_error = got_repo_close(repo);
		if (error == NULL)
			error = repo_error;
	}
	return error;
}

__dead static void
usage_diff(void)
{
	fprintf(stderr, "usage: %s diff [-C number] [-r repository-path] "
	    "[object1 object2]\n", getprogname());
	exit(1);
}

struct print_diff_arg {
	struct got_repository *repo;
	struct got_worktree *worktree;
	int diff_context;
};

static const struct got_error *
print_diff(void *arg, unsigned char status, const char *path,
    struct got_object_id *id)
{
	struct print_diff_arg *a = arg;
	const struct got_error *err = NULL;
	struct got_blob_object *blob1 = NULL;
	FILE *f2 = NULL;
	char *abspath = NULL;
	struct stat sb;

	if (status != GOT_STATUS_MODIFY)
		return NULL;

	err = got_object_open_as_blob(&blob1, a->repo, id, 8192);
	if (err)
		goto done;

	if (asprintf(&abspath, "%s/%s",
	    got_worktree_get_root_path(a->worktree), path) == -1) {
		err = got_error_from_errno();
		goto done;
	}

	f2 = fopen(abspath, "r");
	if (f2 == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	if (lstat(abspath, &sb) == -1) {
		err = got_error_from_errno();
		goto done;
	}

	err = got_diff_blob_file(blob1, f2, sb.st_size, path, a->diff_context,
	    stdout);
done:
	if (blob1)
		got_object_blob_close(blob1);
	if (f2)
		fclose(f2);
	free(abspath);
	return err;
}

static const struct got_error *
cmd_diff(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *cwd = NULL, *repo_path = NULL;
	struct got_object_id *id1 = NULL, *id2 = NULL;
	char *id_str1 = NULL, *id_str2 = NULL;
	int type1, type2;
	int diff_context = 3, ch;
	const char *errstr;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "C:r:")) != -1) {
		switch (ch) {
		case 'C':
			diff_context = strtonum(optarg, 1, INT_MAX, &errstr);
			if (errstr != NULL)
				err(1, "-C option %s", errstr);
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

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno();
		goto done;
	}
	if (argc == 0) {
		if (repo_path)
			errx(1,
			    "-r option can't be used when diffing a work tree");
		error = got_worktree_open(&worktree, cwd);
		if (error)
			goto done;
		repo_path = strdup(got_worktree_get_repo_path(worktree));
		if (repo_path == NULL)
			return got_error_from_errno();
	} else if (argc == 2) {
		id_str1 = argv[0];
		id_str2 = argv[1];
	} else
		usage_diff();

	if (repo_path == NULL) {
		repo_path = getcwd(NULL, 0);
		if (repo_path == NULL)
			return got_error_from_errno();
	}

	error = apply_unveil(repo_path,
	    worktree ? got_worktree_get_root_path(worktree) : NULL);
	if (error)
		goto done;

	error = got_repo_open(&repo, repo_path);
	free(repo_path);
	if (error != NULL)
		goto done;

	if (worktree) {
		struct print_diff_arg arg;
		char *id_str;
		error = got_object_id_str(&id_str,
		    got_worktree_get_base_commit_id(worktree));
		if (error)
			goto done;
		arg.repo = repo;
		arg.worktree = worktree;
		arg.diff_context = diff_context;

		printf("diff %s %s\n", id_str,
		    got_worktree_get_root_path(worktree));
		error = got_worktree_status(worktree, repo, print_diff,
		    &arg, check_cancelled, NULL);
		free(id_str);
		goto done;
	}

	error = got_object_resolve_id_str(&id1, repo, id_str1);
	if (error)
		goto done;

	error = got_object_resolve_id_str(&id2, repo, id_str2);
	if (error)
		goto done;

	error = got_object_get_type(&type1, repo, id1);
	if (error)
		goto done;

	error = got_object_get_type(&type2, repo, id2);
	if (error)
		goto done;

	if (type1 != type2) {
		error = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	switch (type1) {
	case GOT_OBJ_TYPE_BLOB:
		error = got_diff_objects_as_blobs(id1, id2, NULL, NULL,
		    diff_context, repo, stdout);
		break;
	case GOT_OBJ_TYPE_TREE:
		error = got_diff_objects_as_trees(id1, id2, "", "",
		    diff_context, repo, stdout);
		break;
	case GOT_OBJ_TYPE_COMMIT:
		printf("diff %s %s\n", id_str1 ? id_str1 : "/dev/null",
		    id_str2);
		error = got_diff_objects_as_commits(id1, id2, diff_context,
		    repo, stdout);
		break;
	default:
		error = got_error(GOT_ERR_OBJ_TYPE);
	}

done:
	free(id1);
	free(id2);
	if (worktree)
		got_worktree_close(worktree);
	if (repo) {
		const struct got_error *repo_error;
		repo_error = got_repo_close(repo);
		if (error == NULL)
			error = repo_error;
	}
	return error;
}

__dead static void
usage_blame(void)
{
	fprintf(stderr,
	    "usage: %s blame [-c commit] [-r repository-path] path\n",
	    getprogname());
	exit(1);
}

static const struct got_error *
cmd_blame(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *path, *cwd = NULL, *repo_path = NULL, *in_repo_path = NULL;
	struct got_object_id *commit_id = NULL;
	char *commit_id_str = NULL;
	int ch;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "c:r:")) != -1) {
		switch (ch) {
		case 'c':
			commit_id_str = optarg;
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

	if (argc == 1)
		path = argv[0];
	else
		usage_blame();

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno();
		goto done;
	}
	if (repo_path == NULL) {
		error = got_worktree_open(&worktree, cwd);
		if (error && error->code != GOT_ERR_NOT_WORKTREE)
			goto done;
		else
			error = NULL;
		if (worktree) {
			repo_path =
			    strdup(got_worktree_get_repo_path(worktree));
			if (repo_path == NULL)
				error = got_error_from_errno();
			if (error)
				goto done;
		} else {
			repo_path = strdup(cwd);
			if (repo_path == NULL) {
				error = got_error_from_errno();
				goto done;
			}
		}
	}

	error = apply_unveil(repo_path, NULL);
	if (error)
		goto done;

	error = got_repo_open(&repo, repo_path);
	if (error != NULL)
		goto done;

	if (worktree) {
		const char *prefix = got_worktree_get_path_prefix(worktree);
		char *p, *worktree_subdir = cwd +
		    strlen(got_worktree_get_root_path(worktree));
		if (asprintf(&p, "%s%s%s%s%s",
		    prefix, (strcmp(prefix, "/") != 0) ? "/" : "",
		    worktree_subdir, worktree_subdir[0] ? "/" : "",
		    path) == -1) {
			error = got_error_from_errno();
			goto done;
		}
		error = got_repo_map_path(&in_repo_path, repo, p, 0);
		free(p);
	} else {
		error = got_repo_map_path(&in_repo_path, repo, path, 1);
	}
	if (error)
		goto done;

	if (commit_id_str == NULL) {
		struct got_reference *head_ref;
		error = got_ref_open(&head_ref, repo, GOT_REF_HEAD);
		if (error != NULL)
			goto done;
		error = got_ref_resolve(&commit_id, repo, head_ref);
		got_ref_close(head_ref);
		if (error != NULL)
			goto done;
	} else {
		error = got_object_resolve_id_str(&commit_id, repo,
		    commit_id_str);
		if (error != NULL)
			goto done;
	}

	error = got_blame(in_repo_path, commit_id, repo, stdout);
done:
	free(in_repo_path);
	free(repo_path);
	free(cwd);
	free(commit_id);
	if (worktree)
		got_worktree_close(worktree);
	if (repo) {
		const struct got_error *repo_error;
		repo_error = got_repo_close(repo);
		if (error == NULL)
			error = repo_error;
	}
	return error;
}

__dead static void
usage_tree(void)
{
	fprintf(stderr,
	    "usage: %s tree [-c commit] [-r repository-path] [-iR] path\n",
	    getprogname());
	exit(1);
}

static void
print_entry(struct got_tree_entry *te, const char *id, const char *path,
    const char *root_path)
{
	int is_root_path = (strcmp(path, root_path) == 0);

	path += strlen(root_path);
	while (path[0] == '/')
		path++;

	printf("%s%s%s%s%s\n", id ? id : "", path,
	    is_root_path ? "" : "/",
	    te->name, S_ISDIR(te->mode) ? "/" : "");
}

static const struct got_error *
print_tree(const char *path, struct got_object_id *commit_id,
    int show_ids, int recurse, const char *root_path,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object_id *tree_id = NULL;
	struct got_tree_object *tree = NULL;
	const struct got_tree_entries *entries;
	struct got_tree_entry *te;

	err = got_object_id_by_path(&tree_id, repo, commit_id, path);
	if (err)
		goto done;

	err = got_object_open_as_tree(&tree, repo, tree_id);
	if (err)
		goto done;
	entries = got_object_tree_get_entries(tree);
	te = SIMPLEQ_FIRST(&entries->head);
	while (te) {
		char *id = NULL;

		if (sigint_received || sigpipe_received)
			break;

		if (show_ids) {
			char *id_str;
			err = got_object_id_str(&id_str, te->id);
			if (err)
				goto done;
			if (asprintf(&id, "%s ", id_str) == -1) {
				err = got_error_from_errno();
				free(id_str);
				goto done;
			}
			free(id_str);
		}
		print_entry(te, id, path, root_path);
		free(id);

		if (recurse && S_ISDIR(te->mode)) {
			char *child_path;
			if (asprintf(&child_path, "%s%s%s", path,
			    path[0] == '/' && path[1] == '\0' ? "" : "/",
			    te->name) == -1) {
				err = got_error_from_errno();
				goto done;
			}
			err = print_tree(child_path, commit_id, show_ids, 1,
			    root_path, repo);
			free(child_path);
			if (err)
				goto done;
		}

		te = SIMPLEQ_NEXT(te, entry);
	}
done:
	if (tree)
		got_object_tree_close(tree);
	free(tree_id);
	return err;
}

static const struct got_error *
cmd_tree(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	const char *path;
	char *cwd = NULL, *repo_path = NULL, *in_repo_path = NULL;
	struct got_object_id *commit_id = NULL;
	char *commit_id_str = NULL;
	int show_ids = 0, recurse = 0;
	int ch;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "c:r:iR")) != -1) {
		switch (ch) {
		case 'c':
			commit_id_str = optarg;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				err(1, "-r option");
			break;
		case 'i':
			show_ids = 1;
			break;
		case 'R':
			recurse = 1;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 1)
		path = argv[0];
	else if (argc > 1)
		usage_tree();
	else
		path = NULL;

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno();
		goto done;
	}
	if (repo_path == NULL) {
		error = got_worktree_open(&worktree, cwd);
		if (error && error->code != GOT_ERR_NOT_WORKTREE)
			goto done;
		else
			error = NULL;
		if (worktree) {
			repo_path =
			    strdup(got_worktree_get_repo_path(worktree));
			if (repo_path == NULL)
				error = got_error_from_errno();
			if (error)
				goto done;
		} else {
			repo_path = strdup(cwd);
			if (repo_path == NULL) {
				error = got_error_from_errno();
				goto done;
			}
		}
	}

	error = apply_unveil(repo_path, NULL);
	if (error)
		goto done;

	error = got_repo_open(&repo, repo_path);
	if (error != NULL)
		goto done;

	if (path == NULL) {
		if (worktree) {
			char *p, *worktree_subdir = cwd +
			    strlen(got_worktree_get_root_path(worktree));
			if (asprintf(&p, "%s/%s",
			    got_worktree_get_path_prefix(worktree),
			    worktree_subdir) == -1) {
				error = got_error_from_errno();
				goto done;
			}
			error = got_repo_map_path(&in_repo_path, repo, p, 1);
			free(p);
			if (error)
				goto done;
		} else
			path = "/";
	}
	if (in_repo_path == NULL) {
		error = got_repo_map_path(&in_repo_path, repo, path, 1);
		if (error != NULL)
			goto done;
	}

	if (commit_id_str == NULL) {
		struct got_reference *head_ref;
		error = got_ref_open(&head_ref, repo, GOT_REF_HEAD);
		if (error != NULL)
			goto done;
		error = got_ref_resolve(&commit_id, repo, head_ref);
		got_ref_close(head_ref);
		if (error != NULL)
			goto done;
	} else {
		error = got_object_resolve_id_str(&commit_id, repo,
		    commit_id_str);
		if (error != NULL)
			goto done;
	}

	error = print_tree(in_repo_path, commit_id, show_ids, recurse,
	    in_repo_path, repo);
done:
	free(in_repo_path);
	free(repo_path);
	free(cwd);
	free(commit_id);
	if (worktree)
		got_worktree_close(worktree);
	if (repo) {
		const struct got_error *repo_error;
		repo_error = got_repo_close(repo);
		if (error == NULL)
			error = repo_error;
	}
	return error;
}

__dead static void
usage_status(void)
{
	fprintf(stderr, "usage: %s status [worktree-path]\n", getprogname());
	exit(1);
}

static const struct got_error *
print_status(void *arg, unsigned char status, const char *path,
    struct got_object_id *id)
{
	printf("%c  %s\n", status, path);
	return NULL;
}

static const struct got_error *
cmd_status(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *worktree_path = NULL;
	int ch;

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif
	if (argc == 0) {
		worktree_path = getcwd(NULL, 0);
		if (worktree_path == NULL) {
			error = got_error_from_errno();
			goto done;
		}
	} else if (argc == 1) {
		worktree_path = realpath(argv[0], NULL);
		if (worktree_path == NULL) {
			error = got_error_from_errno();
			goto done;
		}
	} else
		usage_status();

	error = got_worktree_open(&worktree, worktree_path);
	if (error != NULL)
		goto done;

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree));
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo),
	    got_worktree_get_root_path(worktree));
	if (error)
		goto done;

	error = got_worktree_status(worktree, repo, print_status, NULL,
	    check_cancelled, NULL);
done:
	free(worktree_path);
	return error;
}
