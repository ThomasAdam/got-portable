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
#include <sys/param.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <locale.h>
#include <ctype.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <time.h>
#include <paths.h>

#include "got_error.h"
#include "got_object.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_path.h"
#include "got_worktree.h"
#include "got_diff.h"
#include "got_commit_graph.h"
#include "got_blame.h"
#include "got_privsep.h"
#include "got_opentemp.h"

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


struct got_cmd {
	const char	 *cmd_name;
	const struct got_error *(*cmd_main)(int, char *[]);
	void		(*cmd_usage)(void);
	const char	*cmd_alias;
};

__dead static void	usage(int);
__dead static void	usage_init(void);
__dead static void	usage_checkout(void);
__dead static void	usage_update(void);
__dead static void	usage_log(void);
__dead static void	usage_diff(void);
__dead static void	usage_blame(void);
__dead static void	usage_tree(void);
__dead static void	usage_status(void);
__dead static void	usage_ref(void);
__dead static void	usage_branch(void);
__dead static void	usage_add(void);
__dead static void	usage_remove(void);
__dead static void	usage_revert(void);
__dead static void	usage_commit(void);
__dead static void	usage_cherrypick(void);
__dead static void	usage_backout(void);
__dead static void	usage_rebase(void);

static const struct got_error*		cmd_init(int, char *[]);
static const struct got_error*		cmd_checkout(int, char *[]);
static const struct got_error*		cmd_update(int, char *[]);
static const struct got_error*		cmd_log(int, char *[]);
static const struct got_error*		cmd_diff(int, char *[]);
static const struct got_error*		cmd_blame(int, char *[]);
static const struct got_error*		cmd_tree(int, char *[]);
static const struct got_error*		cmd_status(int, char *[]);
static const struct got_error*		cmd_ref(int, char *[]);
static const struct got_error*		cmd_branch(int, char *[]);
static const struct got_error*		cmd_add(int, char *[]);
static const struct got_error*		cmd_remove(int, char *[]);
static const struct got_error*		cmd_revert(int, char *[]);
static const struct got_error*		cmd_commit(int, char *[]);
static const struct got_error*		cmd_cherrypick(int, char *[]);
static const struct got_error*		cmd_backout(int, char *[]);
static const struct got_error*		cmd_rebase(int, char *[]);

static struct got_cmd got_commands[] = {
	{ "init",	cmd_init,	usage_init,	"" },
	{ "checkout",	cmd_checkout,	usage_checkout,	"co" },
	{ "update",	cmd_update,	usage_update,	"up" },
	{ "log",	cmd_log,	usage_log,	"" },
	{ "diff",	cmd_diff,	usage_diff,	"" },
	{ "blame",	cmd_blame,	usage_blame,	"" },
	{ "tree",	cmd_tree,	usage_tree,	"" },
	{ "status",	cmd_status,	usage_status,	"st" },
	{ "ref",	cmd_ref,	usage_ref,	"" },
	{ "branch",	cmd_branch,	usage_branch,	"br" },
	{ "add",	cmd_add,	usage_add,	"" },
	{ "remove",	cmd_remove,	usage_remove,	"rm" },
	{ "revert",	cmd_revert,	usage_revert,	"rv" },
	{ "commit",	cmd_commit,	usage_commit,	"ci" },
	{ "cherrypick",	cmd_cherrypick,	usage_cherrypick, "cy" },
	{ "backout",	cmd_backout,	usage_backout,	"bo" },
	{ "rebase",	cmd_rebase,	usage_rebase,	"rb" },
};

static void
list_commands(void)
{
	int i;

	fprintf(stderr, "commands:");
	for (i = 0; i < nitems(got_commands); i++) {
		struct got_cmd *cmd = &got_commands[i];
		fprintf(stderr, " %s", cmd->cmd_name);
	}
	fputc('\n', stderr);
}

int
main(int argc, char *argv[])
{
	struct got_cmd *cmd;
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
			usage(hflag);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;
	optind = 0;

	if (argc <= 0)
		usage(hflag);

	signal(SIGINT, catch_sigint);
	signal(SIGPIPE, catch_sigpipe);

	for (i = 0; i < nitems(got_commands); i++) {
		const struct got_error *error;

		cmd = &got_commands[i];

		if (strcmp(cmd->cmd_name, argv[0]) != 0 &&
		    strcmp(cmd->cmd_alias, argv[0]) != 0)
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
	list_commands();
	return 1;
}

__dead static void
usage(int hflag)
{
	fprintf(stderr, "usage: %s [-h] command [arg ...]\n", getprogname());
	if (hflag)
		list_commands();
	exit(1);
}

static const struct got_error *
get_editor(char **abspath)
{
	const struct got_error *err = NULL;
	const char *editor;

	editor = getenv("VISUAL");
	if (editor == NULL)
		editor = getenv("EDITOR");

	if (editor) {
		err = got_path_find_prog(abspath, editor);
		if (err)
			return err;
	}

	if (*abspath == NULL) {
		*abspath = strdup("/bin/ed");
		if (*abspath == NULL)
			return got_error_from_errno("strdup");
	}

	return NULL;
}

static const struct got_error *
apply_unveil(const char *repo_path, int repo_read_only,
    const char *worktree_path, int create_worktree)
{
	const struct got_error *err;

	if (create_worktree) {
		/* Pre-create work tree path to avoid unveiling its parents. */
		err = got_path_mkdir(worktree_path);

		if (errno == EEXIST) {
			if (got_path_dir_is_empty(worktree_path)) {
				errno = 0;
				err = NULL;
			} else {
				err = got_error_path(worktree_path,
				    GOT_ERR_DIR_NOT_EMPTY);
			}
		}

		if (err && (err->code != GOT_ERR_ERRNO || errno != EISDIR))
			return err;
	}

	if (repo_path && unveil(repo_path, repo_read_only ? "r" : "rwc") != 0)
		return got_error_from_errno2("unveil", repo_path);

	if (worktree_path && unveil(worktree_path, "rwc") != 0)
		return got_error_from_errno2("unveil", worktree_path);

	if (unveil("/tmp", "rwc") != 0)
		return got_error_from_errno2("unveil", "/tmp");

	err = got_privsep_unveil_exec_helpers();
	if (err != NULL)
		return err;

	if (unveil(NULL, NULL) != 0)
		return got_error_from_errno("unveil");

	return NULL;
}

__dead static void
usage_init(void)
{
	fprintf(stderr, "usage: %s init path\n", getprogname());
	exit(1);
}

static const struct got_error *
cmd_init(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	char *repo_path = NULL;
	int ch;

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			usage_init();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath unveil", NULL) == -1)
		err(1, "pledge");
#endif
	if (argc != 1)
		usage_init();

	repo_path = strdup(argv[0]);
	if (repo_path == NULL)
		return got_error_from_errno("strdup");

	got_path_strip_trailing_slashes(repo_path);

	error = got_path_mkdir(repo_path);
	if (error &&
	    !(error->code == GOT_ERR_ERRNO && errno == EEXIST))
		goto done;

	error = apply_unveil(repo_path, 0, NULL, 0);
	if (error)
		goto done;

	error = got_repo_init(repo_path);
	if (error != NULL)
		goto done;

done:
	free(repo_path);
	return error;
}

__dead static void
usage_checkout(void)
{
	fprintf(stderr, "usage: %s checkout [-b branch] [-c commit] "
	    "[-p prefix] repository-path [worktree-path]\n", getprogname());
	exit(1);
}

static void
checkout_progress(void *arg, unsigned char status, const char *path)
{
	char *worktree_path = arg;

	/* Base commit bump happens silently. */
	if (status == GOT_STATUS_BUMP_BASE)
		return;

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
check_linear_ancestry(struct got_object_id *commit_id,
    struct got_object_id *base_commit_id, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object_id *yca_id;

	err = got_commit_graph_find_youngest_common_ancestor(&yca_id,
	    commit_id, base_commit_id, repo);
	if (err)
		return err;

	if (yca_id == NULL)
		return got_error(GOT_ERR_ANCESTRY);

	/*
	 * Require a straight line of history between the target commit
	 * and the work tree's base commit.
	 *
	 * Non-linear situations such as this require a rebase:
	 *
	 * (commit) D       F (base_commit)
	 *           \     /
	 *            C   E
	 *             \ /
	 *              B (yca)
	 *              |
	 *              A
	 *
	 * 'got update' only handles linear cases:
	 * Update forwards in time:  A (base/yca) - B - C - D (commit)
	 * Update backwards in time: D (base) - C - B - A (commit/yca)
	 */
	if (got_object_id_cmp(commit_id, yca_id) != 0 &&
	    got_object_id_cmp(base_commit_id, yca_id) != 0)
		return got_error(GOT_ERR_ANCESTRY);

	free(yca_id);
	return NULL;
}

static const struct got_error *
check_same_branch(struct got_object_id *commit_id,
    struct got_reference *head_ref, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_commit_graph *graph = NULL;
	struct got_object_id *head_commit_id = NULL;
	int is_same_branch = 0;

	err = got_ref_resolve(&head_commit_id, repo, head_ref);
	if (err)
		goto done;

	err = got_commit_graph_open(&graph, head_commit_id, "/", 1, repo);
	if (err)
		goto done;

	err = got_commit_graph_iter_start(graph, head_commit_id, repo);
	if (err)
		goto done;

	for (;;) {
		struct got_object_id *id;
		err = got_commit_graph_iter_next(&id, graph);
		if (err) {
			if (err->code == GOT_ERR_ITER_COMPLETED) {
				err = NULL;
				break;
			}
			else if (err->code != GOT_ERR_ITER_NEED_MORE)
				break;
			err = got_commit_graph_fetch_commits(graph, 1,
			    repo);
			if (err)
				break;
		}

		if (id) {
			if (got_object_id_cmp(id, commit_id) == 0) {
				is_same_branch = 1;
				break;
			}
		}
	}
done:
	if (graph)
		got_commit_graph_close(graph);
	free(head_commit_id);
	if (!err && !is_same_branch)
		err = got_error(GOT_ERR_ANCESTRY);
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
	const char *branch_name = GOT_REF_HEAD;
	char *commit_id_str = NULL;
	int ch, same_path_prefix;

	while ((ch = getopt(argc, argv, "b:c:p:")) != -1) {
		switch (ch) {
		case 'b':
			branch_name = optarg;
			break;
		case 'c':
			commit_id_str = strdup(optarg);
			if (commit_id_str == NULL)
				return got_error_from_errno("strdup");
			break;
		case 'p':
			path_prefix = optarg;
			break;
		default:
			usage_checkout();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec sendfd "
	    "unveil", NULL) == -1)
		err(1, "pledge");
#endif
	if (argc == 1) {
		char *cwd, *base, *dotgit;
		repo_path = realpath(argv[0], NULL);
		if (repo_path == NULL)
			return got_error_from_errno2("realpath", argv[0]);
		cwd = getcwd(NULL, 0);
		if (cwd == NULL) {
			error = got_error_from_errno("getcwd");
			goto done;
		}
		if (path_prefix[0]) {
			base = basename(path_prefix);
			if (base == NULL) {
				error = got_error_from_errno2("basename",
				    path_prefix);
				goto done;
			}
		} else {
			base = basename(repo_path);
			if (base == NULL) {
				error = got_error_from_errno2("basename",
				    repo_path);
				goto done;
			}
		}
		dotgit = strstr(base, ".git");
		if (dotgit)
			*dotgit = '\0';
		if (asprintf(&worktree_path, "%s/%s", cwd, base) == -1) {
			error = got_error_from_errno("asprintf");
			free(cwd);
			goto done;
		}
		free(cwd);
	} else if (argc == 2) {
		repo_path = realpath(argv[0], NULL);
		if (repo_path == NULL) {
			error = got_error_from_errno2("realpath", argv[0]);
			goto done;
		}
		worktree_path = realpath(argv[1], NULL);
		if (worktree_path == NULL) {
			error = got_error_from_errno2("realpath", argv[1]);
			goto done;
		}
	} else
		usage_checkout();

	got_path_strip_trailing_slashes(repo_path);
	got_path_strip_trailing_slashes(worktree_path);

	error = got_repo_open(&repo, repo_path);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 0, worktree_path, 1);
	if (error)
		goto done;

	error = got_ref_open(&head_ref, repo, branch_name, 0);
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
		error = got_repo_match_object_id_prefix(&commit_id,
		    commit_id_str, GOT_OBJ_TYPE_COMMIT, repo);
		if (error != NULL)
			goto done;
		error = check_linear_ancestry(commit_id,
		    got_worktree_get_base_commit_id(worktree), repo);
		if (error != NULL) {
			free(commit_id);
			goto done;
		}
		error = check_same_branch(commit_id, head_ref, repo);
		if (error)
			goto done;
		error = got_worktree_set_base_commit_id(worktree, repo,
		    commit_id);
		free(commit_id);
		if (error)
			goto done;
	}

	error = got_worktree_checkout_files(worktree, "", repo,
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
	fprintf(stderr, "usage: %s update [-b branch] [-c commit] [path]\n",
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

	/* Base commit bump happens silently. */
	if (status == GOT_STATUS_BUMP_BASE)
		return;

	while (path[0] == '/')
		path++;
	printf("%c  %s\n", status, path);
}

static const struct got_error *
switch_head_ref(struct got_reference *head_ref,
    struct got_object_id *commit_id, struct got_worktree *worktree,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *base_id_str;
	int ref_has_moved = 0;

	/* Trivial case: switching between two different references. */
	if (strcmp(got_ref_get_name(head_ref),
	    got_worktree_get_head_ref_name(worktree)) != 0) {
		printf("Switching work tree from %s to %s\n",
		    got_worktree_get_head_ref_name(worktree),
		    got_ref_get_name(head_ref));
		return got_worktree_set_head_ref(worktree, head_ref);
	}

	err = check_linear_ancestry(commit_id,
	    got_worktree_get_base_commit_id(worktree), repo);
	if (err) {
		if (err->code != GOT_ERR_ANCESTRY)
			return err;
		ref_has_moved = 1;
	}
	if (!ref_has_moved)
		return NULL;

	/* Switching to a rebased branch with the same reference name. */
	err = got_object_id_str(&base_id_str,
	    got_worktree_get_base_commit_id(worktree));
	if (err)
		return err;
	printf("Reference %s now points at a different branch\n",
	    got_worktree_get_head_ref_name(worktree));
	printf("Switching work tree from %s to %s\n", base_id_str,
	    got_worktree_get_head_ref_name(worktree));
	return NULL;
}

static const struct got_error *
cmd_update(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *worktree_path = NULL, *path = NULL;
	struct got_object_id *commit_id = NULL;
	char *commit_id_str = NULL;
	const char *branch_name = NULL;
	struct got_reference *head_ref = NULL;
	int ch, did_something = 0;

	while ((ch = getopt(argc, argv, "b:c:")) != -1) {
		switch (ch) {
		case 'b':
			branch_name = optarg;
			break;
		case 'c':
			commit_id_str = strdup(optarg);
			if (commit_id_str == NULL)
				return got_error_from_errno("strdup");
			break;
		default:
			usage_update();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec sendfd "
	    "unveil", NULL) == -1)
		err(1, "pledge");
#endif
	worktree_path = getcwd(NULL, 0);
	if (worktree_path == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}
	error = got_worktree_open(&worktree, worktree_path);
	if (error)
		goto done;

	if (argc == 0) {
		path = strdup("");
		if (path == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
	} else if (argc == 1) {
		error = got_worktree_resolve_path(&path, worktree, argv[0]);
		if (error)
			goto done;
	} else
		usage_update();

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree));
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 0,
	    got_worktree_get_root_path(worktree), 0);
	if (error)
		goto done;

	error = got_ref_open(&head_ref, repo, branch_name ? branch_name :
	    got_worktree_get_head_ref_name(worktree), 0);
	if (error != NULL)
		goto done;
	if (commit_id_str == NULL) {
		error = got_ref_resolve(&commit_id, repo, head_ref);
		if (error != NULL)
			goto done;
		error = got_object_id_str(&commit_id_str, commit_id);
		if (error != NULL)
			goto done;
	} else {
		error = got_repo_match_object_id_prefix(&commit_id,
		    commit_id_str, GOT_OBJ_TYPE_COMMIT, repo);
		if (error != NULL)
			goto done;
	}

	if (branch_name) {
		struct got_object_id *head_commit_id;
		if (strlen(path) != 0) {
			fprintf(stderr, "%s: switching between branches "
			    "requires that the entire work tree "
			    "gets updated, not just '%s'\n",
			    getprogname(), path);
			error = got_error(GOT_ERR_BAD_PATH);
			goto done;
		}
		error = got_ref_resolve(&head_commit_id, repo, head_ref);
		if (error)
			goto done;
		error = check_linear_ancestry(commit_id, head_commit_id, repo);
		free(head_commit_id);
		if (error != NULL)
			goto done;
		error = check_same_branch(commit_id, head_ref, repo);
		if (error)
			goto done;
		error = switch_head_ref(head_ref, commit_id, worktree, repo);
		if (error)
			goto done;
	} else {
		error = check_linear_ancestry(commit_id,
		    got_worktree_get_base_commit_id(worktree), repo);
		if (error != NULL) {
			if (error->code == GOT_ERR_ANCESTRY)
				error = got_error(GOT_ERR_BRANCH_MOVED);
			goto done;
		}
		error = check_same_branch(commit_id, head_ref, repo);
		if (error)
			goto done;
	}

	if (got_object_id_cmp(got_worktree_get_base_commit_id(worktree),
	    commit_id) != 0) {
		error = got_worktree_set_base_commit_id(worktree, repo,
		    commit_id);
		if (error)
			goto done;
	}

	error = got_worktree_checkout_files(worktree, path, repo,
	    update_progress, &did_something, check_cancelled, NULL);
	if (error != NULL)
		goto done;

	if (did_something)
		printf("Updated to commit %s\n", commit_id_str);
	else
		printf("Already up-to-date\n");
done:
	free(worktree_path);
	free(path);
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
	struct got_diff_blob_output_unidiff_arg arg;

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
	arg.diff_context = diff_context;
	arg.outfile = stdout;
	err = got_diff_tree(tree1, tree2, "", "", repo,
	    got_diff_blob_output_unidiff, &arg);
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
		if (strncmp(name, "got/", 4) == 0)
			continue;
		if (strncmp(name, "heads/", 6) == 0)
			name += 6;
		if (strncmp(name, "remotes/", 8) == 0)
			name += 8;
		s = refs_str;
		if (asprintf(&refs_str, "%s%s%s", s ? s : "", s ? ", " : "",
		    name) == -1) {
			err = got_error_from_errno("asprintf");
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
	id_str = NULL;
	free(refs_str);
	refs_str = NULL;
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
		return got_error_from_errno("strdup");

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

	if (fflush(stdout) != 0 && err == NULL)
		err = got_error_from_errno("fflush");
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
	for (;;) {
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
	fprintf(stderr, "usage: %s log [-b] [-c commit] [-C number] [ -l N ] [-p] "
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

	SIMPLEQ_INIT(&refs);

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc exec sendfd unveil",
	    NULL)
	    == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "bpc:C:l:r:")) != -1) {
		switch (ch) {
		case 'b':
			first_parent_traversal = 1;
			break;
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
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				err(1, "-r option");
			got_path_strip_trailing_slashes(repo_path);
			break;
		default:
			usage_log();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_worktree_open(&worktree, cwd);
	if (error && error->code != GOT_ERR_NOT_WORKTREE)
		goto done;
	error = NULL;

	if (argc == 0) {
		path = strdup("");
		if (path == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
	} else if (argc == 1) {
		if (worktree) {
			error = got_worktree_resolve_path(&path, worktree,
			    argv[0]);
			if (error)
				goto done;
		} else {
			path = strdup(argv[0]);
			if (path == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		}
	} else
		usage_log();

	if (repo_path == NULL) {
		repo_path = worktree ?
		    strdup(got_worktree_get_repo_path(worktree)) : strdup(cwd);
	}
	if (repo_path == NULL) {
		error = got_error_from_errno("strdup");
		goto done;
	}

	error = got_repo_open(&repo, repo_path);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 1,
	    worktree ? got_worktree_get_root_path(worktree) : NULL, 0);
	if (error)
		goto done;

	if (start_commit == NULL) {
		struct got_reference *head_ref;
		error = got_ref_open(&head_ref, repo,
		    worktree ? got_worktree_get_head_ref_name(worktree)
		    : GOT_REF_HEAD, 0);
		if (error != NULL)
			return error;
		error = got_ref_resolve(&id, repo, head_ref);
		got_ref_close(head_ref);
		if (error != NULL)
			return error;
		error = got_object_open_as_commit(&commit, repo, id);
	} else {
		struct got_reference *ref;
		error = got_ref_open(&ref, repo, start_commit, 0);
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
					error = got_error_from_errno(
					    "got_object_id_dup");
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
			error = got_repo_match_object_id_prefix(&id,
			    start_commit, GOT_OBJ_TYPE_COMMIT, repo);
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
	got_ref_list_free(&refs);
	return error;
}

__dead static void
usage_diff(void)
{
	fprintf(stderr, "usage: %s diff [-C number] [-r repository-path] "
	    "[object1 object2 | path]\n", getprogname());
	exit(1);
}

struct print_diff_arg {
	struct got_repository *repo;
	struct got_worktree *worktree;
	int diff_context;
	const char *id_str;
	int header_shown;
};

static const struct got_error *
print_diff(void *arg, unsigned char status, const char *path,
    struct got_object_id *blob_id, struct got_object_id *commit_id)
{
	struct print_diff_arg *a = arg;
	const struct got_error *err = NULL;
	struct got_blob_object *blob1 = NULL;
	FILE *f2 = NULL;
	char *abspath = NULL;
	struct stat sb;

	if (status != GOT_STATUS_MODIFY && status != GOT_STATUS_ADD &&
	    status != GOT_STATUS_DELETE && status != GOT_STATUS_CONFLICT)
		return NULL;

	if (!a->header_shown) {
		printf("diff %s %s\n", a->id_str,
		    got_worktree_get_root_path(a->worktree));
		a->header_shown = 1;
	}

	if (status != GOT_STATUS_ADD) {
		err = got_object_open_as_blob(&blob1, a->repo, blob_id, 8192);
		if (err)
			goto done;

	}

	if (status != GOT_STATUS_DELETE) {
		if (asprintf(&abspath, "%s/%s",
		    got_worktree_get_root_path(a->worktree), path) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}

		f2 = fopen(abspath, "r");
		if (f2 == NULL) {
			err = got_error_from_errno2("fopen", abspath);
			goto done;
		}
		if (lstat(abspath, &sb) == -1) {
			err = got_error_from_errno2("lstat", abspath);
			goto done;
		}
	} else
		sb.st_size = 0;

	err = got_diff_blob_file(blob1, f2, sb.st_size, path, a->diff_context,
	    stdout);
done:
	if (blob1)
		got_object_blob_close(blob1);
	if (f2 && fclose(f2) != 0 && err == NULL)
		err = got_error_from_errno("fclose");
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
	const char *id_str1 = NULL, *id_str2 = NULL;
	char *label1 = NULL, *label2 = NULL;
	int type1, type2;
	int diff_context = 3, ch;
	const char *errstr;
	char *path = NULL;

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
			got_path_strip_trailing_slashes(repo_path);
			break;
		default:
			usage_diff();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}
	error = got_worktree_open(&worktree, cwd);
	if (error && error->code != GOT_ERR_NOT_WORKTREE)
		goto done;
	if (argc <= 1) {
		if (worktree == NULL) {
			error = got_error(GOT_ERR_NOT_WORKTREE);
			goto done;
		}
		if (repo_path)
			errx(1,
			    "-r option can't be used when diffing a work tree");
		repo_path = strdup(got_worktree_get_repo_path(worktree));
		if (repo_path == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
		if (argc == 1) {
			error = got_worktree_resolve_path(&path, worktree,
			    argv[0]);
			if (error)
				goto done;
		} else {
			path = strdup("");
			if (path == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		}
	} else if (argc == 2) {
		id_str1 = argv[0];
		id_str2 = argv[1];
		if (worktree && repo_path == NULL) {
			repo_path =
			    strdup(got_worktree_get_repo_path(worktree));
			if (repo_path == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		}
	} else
		usage_diff();

	if (repo_path == NULL) {
		repo_path = getcwd(NULL, 0);
		if (repo_path == NULL)
			return got_error_from_errno("getcwd");
	}

	error = got_repo_open(&repo, repo_path);
	free(repo_path);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 1,
	    worktree ? got_worktree_get_root_path(worktree) : NULL, 0);
	if (error)
		goto done;

	if (argc <= 1) {
		struct print_diff_arg arg;
		char *id_str;
		error = got_object_id_str(&id_str,
		    got_worktree_get_base_commit_id(worktree));
		if (error)
			goto done;
		arg.repo = repo;
		arg.worktree = worktree;
		arg.diff_context = diff_context;
		arg.id_str = id_str;
		arg.header_shown = 0;

		error = got_worktree_status(worktree, path, repo, print_diff,
		    &arg, check_cancelled, NULL);
		free(id_str);
		goto done;
	}

	error = got_repo_match_object_id_prefix(&id1, id_str1,
	    GOT_OBJ_TYPE_ANY, repo);
	if (error) {
		struct got_reference *ref;
		if (error->code != GOT_ERR_BAD_OBJ_ID_STR)
			goto done;
		error = got_ref_open(&ref, repo, id_str1, 0);
		if (error != NULL)
			goto done;
		label1 = strdup(got_ref_get_name(ref));
		if (label1 == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
		error = got_ref_resolve(&id1, repo, ref);
		got_ref_close(ref);
		if (error != NULL)
			goto done;
	} else {
		label1 = strdup(id_str1);
		if (label1 == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
	}

	error = got_repo_match_object_id_prefix(&id2, id_str2,
	    GOT_OBJ_TYPE_ANY, repo);
	if (error) {
		struct got_reference *ref;
		if (error->code != GOT_ERR_BAD_OBJ_ID_STR)
			goto done;
		error = got_ref_open(&ref, repo, id_str2, 0);
		if (error != NULL)
			goto done;
		label2 = strdup(got_ref_get_name(ref));
		if (label2 == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
		error = got_ref_resolve(&id2, repo, ref);
		got_ref_close(ref);
		if (error != NULL)
			goto done;
	} else {
		label2 = strdup(id_str2);
		if (label2 == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
	}

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
		printf("diff %s %s\n", label1, label2);
		error = got_diff_objects_as_commits(id1, id2, diff_context,
		    repo, stdout);
		break;
	default:
		error = got_error(GOT_ERR_OBJ_TYPE);
	}

done:
	free(label1);
	free(label2);
	free(id1);
	free(id2);
	free(path);
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
			got_path_strip_trailing_slashes(repo_path);
			break;
		default:
			usage_blame();
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
		error = got_error_from_errno("getcwd");
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
				error = got_error_from_errno("strdup");
			if (error)
				goto done;
		} else {
			repo_path = strdup(cwd);
			if (repo_path == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		}
	}

	error = got_repo_open(&repo, repo_path);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 1, NULL, 0);
	if (error)
		goto done;

	if (worktree) {
		const char *prefix = got_worktree_get_path_prefix(worktree);
		char *p, *worktree_subdir = cwd +
		    strlen(got_worktree_get_root_path(worktree));
		if (asprintf(&p, "%s%s%s%s%s",
		    prefix, (strcmp(prefix, "/") != 0) ? "/" : "",
		    worktree_subdir, worktree_subdir[0] ? "/" : "",
		    path) == -1) {
			error = got_error_from_errno("asprintf");
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
		error = got_ref_open(&head_ref, repo, GOT_REF_HEAD, 0);
		if (error != NULL)
			goto done;
		error = got_ref_resolve(&commit_id, repo, head_ref);
		got_ref_close(head_ref);
		if (error != NULL)
			goto done;
	} else {
		error = got_repo_match_object_id_prefix(&commit_id,
		    commit_id_str, GOT_OBJ_TYPE_COMMIT, repo);
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
	    is_root_path ? "" : "/", te->name,
	    S_ISDIR(te->mode) ? "/" : ((te->mode & S_IXUSR) ? "*" : ""));
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
				err = got_error_from_errno("asprintf");
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
				err = got_error_from_errno("asprintf");
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
			got_path_strip_trailing_slashes(repo_path);
			break;
		case 'i':
			show_ids = 1;
			break;
		case 'R':
			recurse = 1;
			break;
		default:
			usage_tree();
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
		error = got_error_from_errno("getcwd");
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
				error = got_error_from_errno("strdup");
			if (error)
				goto done;
		} else {
			repo_path = strdup(cwd);
			if (repo_path == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		}
	}

	error = got_repo_open(&repo, repo_path);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 1, NULL, 0);
	if (error)
		goto done;

	if (path == NULL) {
		if (worktree) {
			char *p, *worktree_subdir = cwd +
			    strlen(got_worktree_get_root_path(worktree));
			if (asprintf(&p, "%s/%s",
			    got_worktree_get_path_prefix(worktree),
			    worktree_subdir) == -1) {
				error = got_error_from_errno("asprintf");
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
		error = got_ref_open(&head_ref, repo, GOT_REF_HEAD, 0);
		if (error != NULL)
			goto done;
		error = got_ref_resolve(&commit_id, repo, head_ref);
		got_ref_close(head_ref);
		if (error != NULL)
			goto done;
	} else {
		error = got_repo_match_object_id_prefix(&commit_id,
		    commit_id_str, GOT_OBJ_TYPE_COMMIT, repo);
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
	fprintf(stderr, "usage: %s status [path]\n", getprogname());
	exit(1);
}

static const struct got_error *
print_status(void *arg, unsigned char status, const char *path,
    struct got_object_id *blob_id, struct got_object_id *commit_id)
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
	char *cwd = NULL, *path = NULL;
	int ch;

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			usage_status();
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
	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_worktree_open(&worktree, cwd);
	if (error != NULL)
		goto done;

	if (argc == 0) {
		path = strdup("");
		if (path == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
	} else if (argc == 1) {
		error = got_worktree_resolve_path(&path, worktree, argv[0]);
		if (error)
			goto done;
	} else
		usage_status();

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree));
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 1,
	    got_worktree_get_root_path(worktree), 0);
	if (error)
		goto done;

	error = got_worktree_status(worktree, path, repo, print_status, NULL,
	    check_cancelled, NULL);
done:
	free(cwd);
	free(path);
	return error;
}

__dead static void
usage_ref(void)
{
	fprintf(stderr,
	    "usage: %s ref [-r repository] -l | -d name | name target\n",
	    getprogname());
	exit(1);
}

static const struct got_error *
list_refs(struct got_repository *repo)
{
	static const struct got_error *err = NULL;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;

	SIMPLEQ_INIT(&refs);
	err = got_ref_list(&refs, repo);
	if (err)
		return err;

	SIMPLEQ_FOREACH(re, &refs, entry) {
		char *refstr;
		refstr = got_ref_to_str(re->ref);
		if (refstr == NULL)
			return got_error_from_errno("got_ref_to_str");
		printf("%s: %s\n", got_ref_get_name(re->ref), refstr);
		free(refstr);
	}

	got_ref_list_free(&refs);
	return NULL;
}

static const struct got_error *
delete_ref(struct got_repository *repo, const char *refname)
{
	const struct got_error *err = NULL;
	struct got_reference *ref;

	err = got_ref_open(&ref, repo, refname, 0);
	if (err)
		return err;

	err = got_ref_delete(ref, repo);
	got_ref_close(ref);
	return err;
}

static const struct got_error *
add_ref(struct got_repository *repo, const char *refname, const char *target)
{
	const struct got_error *err = NULL;
	struct got_object_id *id;
	struct got_reference *ref = NULL;

	err = got_repo_match_object_id_prefix(&id, target, GOT_OBJ_TYPE_ANY,
	    repo);
	if (err) {
		struct got_reference *target_ref;

		if (err->code != GOT_ERR_BAD_OBJ_ID_STR)
			return err;
		err = got_ref_open(&target_ref, repo, target, 0);
		if (err)
			return err;
		err = got_ref_resolve(&id, repo, target_ref);
		got_ref_close(target_ref);
		if (err)
			return err;
	}

	err = got_ref_alloc(&ref, refname, id);
	if (err)
		goto done;

	err = got_ref_write(ref, repo);
done:
	if (ref)
		got_ref_close(ref);
	free(id);
	return err;
}

static const struct got_error *
cmd_ref(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *cwd = NULL, *repo_path = NULL;
	int ch, do_list = 0;
	const char *delref = NULL;

	/* TODO: Add -s option for adding symbolic references. */
	while ((ch = getopt(argc, argv, "d:r:l")) != -1) {
		switch (ch) {
		case 'd':
			delref = optarg;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				err(1, "-r option");
			got_path_strip_trailing_slashes(repo_path);
			break;
		case 'l':
			do_list = 1;
			break;
		default:
			usage_ref();
			/* NOTREACHED */
		}
	}

	if (do_list && delref)
		errx(1, "-l and -d options are mutually exclusive\n");

	argc -= optind;
	argv += optind;

	if (do_list || delref) {
		if (argc > 0)
			usage_ref();
	} else if (argc != 2)
		usage_ref();

#ifndef PROFILE
	if (do_list) {
		if (pledge("stdio rpath wpath flock proc exec sendfd unveil",
		    NULL) == -1)
			err(1, "pledge");
	} else {
		if (pledge("stdio rpath wpath cpath fattr flock proc exec "
		    "sendfd unveil", NULL) == -1)
			err(1, "pledge");
	}
#endif
	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
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
				error = got_error_from_errno("strdup");
			if (error)
				goto done;
		} else {
			repo_path = strdup(cwd);
			if (repo_path == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		}
	}

	error = got_repo_open(&repo, repo_path);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), do_list,
	    worktree ? got_worktree_get_root_path(worktree) : NULL, 0);
	if (error)
		goto done;

	if (do_list)
		error = list_refs(repo);
	else if (delref)
		error = delete_ref(repo, delref);
	else
		error = add_ref(repo, argv[0], argv[1]);
done:
	if (repo)
		got_repo_close(repo);
	if (worktree)
		got_worktree_close(worktree);
	free(cwd);
	free(repo_path);
	return error;
}

__dead static void
usage_branch(void)
{
	fprintf(stderr,
	    "usage: %s branch [-r repository] -l | -d name | "
	    "name [base-branch]\n", getprogname());
	exit(1);
}

static const struct got_error *
list_branches(struct got_repository *repo)
{
	static const struct got_error *err = NULL;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;

	SIMPLEQ_INIT(&refs);
	err = got_ref_list(&refs, repo);
	if (err)
		return err;

	SIMPLEQ_FOREACH(re, &refs, entry) {
		const char *refname;
		char *refstr;
		refname = got_ref_get_name(re->ref);
		if (strncmp(refname, "refs/heads/", 11) != 0)
			continue;
		refname += 11;
		refstr = got_ref_to_str(re->ref);
		if (refstr == NULL)
			return got_error_from_errno("got_ref_to_str");
		printf("%s: %s\n", refname, refstr);
		free(refstr);
	}

	got_ref_list_free(&refs);
	return NULL;
}

static const struct got_error *
delete_branch(struct got_repository *repo, const char *branch_name)
{
	const struct got_error *err = NULL;
	struct got_reference *ref;
	char *refname;

	if (asprintf(&refname, "refs/heads/%s", branch_name) == -1)
		return got_error_from_errno("asprintf");

	err = got_ref_open(&ref, repo, refname, 0);
	if (err)
		goto done;

	err = got_ref_delete(ref, repo);
	got_ref_close(ref);
done:
	free(refname);
	return err;
}

static const struct got_error *
add_branch(struct got_repository *repo, const char *branch_name,
    const char *base_branch)
{
	const struct got_error *err = NULL;
	struct got_object_id *id = NULL;
	struct got_reference *ref = NULL;
	char *base_refname = NULL, *refname = NULL;
	struct got_reference *base_ref;

	if (strcmp(GOT_REF_HEAD, base_branch) == 0) {
		base_refname = strdup(GOT_REF_HEAD);
		if (base_refname == NULL)
			return got_error_from_errno("strdup");
	} else if (asprintf(&base_refname, "refs/heads/%s", base_branch) == -1)
		return got_error_from_errno("asprintf");

	err = got_ref_open(&base_ref, repo, base_refname, 0);
	if (err)
		goto done;
	err = got_ref_resolve(&id, repo, base_ref);
	got_ref_close(base_ref);
	if (err)
		goto done;

	if (asprintf(&refname, "refs/heads/%s", branch_name) == -1) {
		 err = got_error_from_errno("asprintf");
		 goto done;
	}

	err = got_ref_open(&ref, repo, refname, 0);
	if (err == NULL) {
		err = got_error(GOT_ERR_BRANCH_EXISTS);
		goto done;
	} else if (err->code != GOT_ERR_NOT_REF)
		goto done;

	err = got_ref_alloc(&ref, refname, id);
	if (err)
		goto done;

	err = got_ref_write(ref, repo);
done:
	if (ref)
		got_ref_close(ref);
	free(id);
	free(base_refname);
	free(refname);
	return err;
}

static const struct got_error *
cmd_branch(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *cwd = NULL, *repo_path = NULL;
	int ch, do_list = 0;
	const char *delref = NULL;

	while ((ch = getopt(argc, argv, "d:r:l")) != -1) {
		switch (ch) {
		case 'd':
			delref = optarg;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				err(1, "-r option");
			got_path_strip_trailing_slashes(repo_path);
			break;
		case 'l':
			do_list = 1;
			break;
		default:
			usage_branch();
			/* NOTREACHED */
		}
	}

	if (do_list && delref)
		errx(1, "-l and -d options are mutually exclusive\n");

	argc -= optind;
	argv += optind;

	if (do_list || delref) {
		if (argc > 0)
			usage_branch();
	} else if (argc < 1 || argc > 2)
		usage_branch();

#ifndef PROFILE
	if (do_list) {
		if (pledge("stdio rpath wpath flock proc exec sendfd unveil",
		    NULL) == -1)
			err(1, "pledge");
	} else {
		if (pledge("stdio rpath wpath cpath fattr flock proc exec "
		    "sendfd unveil", NULL) == -1)
			err(1, "pledge");
	}
#endif
	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
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
				error = got_error_from_errno("strdup");
			if (error)
				goto done;
		} else {
			repo_path = strdup(cwd);
			if (repo_path == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		}
	}

	error = got_repo_open(&repo, repo_path);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), do_list,
	    worktree ? got_worktree_get_root_path(worktree) : NULL, 0);
	if (error)
		goto done;

	if (do_list)
		error = list_branches(repo);
	else if (delref)
		error = delete_branch(repo, delref);
	else {
		const char *base_branch;
		if (argc == 1) {
			base_branch = worktree ?
			    got_worktree_get_head_ref_name(worktree) :
			    GOT_REF_HEAD;
		} else
			base_branch = argv[1];
		error = add_branch(repo, argv[0], base_branch);
	}
done:
	if (repo)
		got_repo_close(repo);
	if (worktree)
		got_worktree_close(worktree);
	free(cwd);
	free(repo_path);
	return error;
}

__dead static void
usage_add(void)
{
	fprintf(stderr, "usage: %s add file-path ...\n", getprogname());
	exit(1);
}

static const struct got_error *
cmd_add(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *cwd = NULL;
	struct got_pathlist_head paths;
	struct got_pathlist_entry *pe;
	int ch, x;

	TAILQ_INIT(&paths);

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			usage_add();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage_add();

	/* make sure each file exists before doing anything halfway */
	for (x = 0; x < argc; x++) {
		char *path = realpath(argv[x], NULL);
		if (path == NULL) {
			error = got_error_from_errno2("realpath", argv[x]);
			goto done;
		}
		free(path);
	}

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_worktree_open(&worktree, cwd);
	if (error)
		goto done;

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree));
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 1,
	    got_worktree_get_root_path(worktree), 0);
	if (error)
		goto done;

	for (x = 0; x < argc; x++) {
		char *path = realpath(argv[x], NULL);
		if (path == NULL) {
			error = got_error_from_errno2("realpath", argv[x]);
			goto done;
		}

		got_path_strip_trailing_slashes(path);
		error = got_pathlist_insert(&pe, &paths, path, NULL);
		if (error) {
			free(path);
			goto done;
		}
	}
	error = got_worktree_schedule_add(worktree, &paths, print_status,
	    NULL, repo);
done:
	if (repo)
		got_repo_close(repo);
	if (worktree)
		got_worktree_close(worktree);
	TAILQ_FOREACH(pe, &paths, entry)
		free((char *)pe->path);
	got_pathlist_free(&paths);
	free(cwd);
	return error;
}

__dead static void
usage_remove(void)
{
	fprintf(stderr, "usage: %s remove [-f] file-path ...\n", getprogname());
	exit(1);
}

static const struct got_error *
cmd_remove(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_worktree *worktree = NULL;
	struct got_repository *repo = NULL;
	char *cwd = NULL;
	struct got_pathlist_head paths;
	struct got_pathlist_entry *pe;
	int ch, i, delete_local_mods = 0;

	TAILQ_INIT(&paths);

	while ((ch = getopt(argc, argv, "f")) != -1) {
		switch (ch) {
		case 'f':
			delete_local_mods = 1;
			break;
		default:
			usage_add();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage_remove();

	/* make sure each file exists before doing anything halfway */
	for (i = 0; i < argc; i++) {
		char *path = realpath(argv[i], NULL);
		if (path == NULL) {
			error = got_error_from_errno2("realpath", argv[i]);
			goto done;
		}
		free(path);
	}

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}
	error = got_worktree_open(&worktree, cwd);
	if (error)
		goto done;

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree));
	if (error)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 1,
	    got_worktree_get_root_path(worktree), 0);
	if (error)
		goto done;

	for (i = 0; i < argc; i++) {
		char *path = realpath(argv[i], NULL);
		if (path == NULL) {
			error = got_error_from_errno2("realpath", argv[i]);
			goto done;
		}

		got_path_strip_trailing_slashes(path);
		error = got_pathlist_insert(&pe, &paths, path, NULL);
		if (error) {
			free(path);
			goto done;
		}
	}
	error = got_worktree_schedule_delete(worktree, &paths,
	    delete_local_mods, print_status, NULL, repo);
	if (error)
		goto done;
done:
	if (repo)
		got_repo_close(repo);
	if (worktree)
		got_worktree_close(worktree);
	TAILQ_FOREACH(pe, &paths, entry)
		free((char *)pe->path);
	got_pathlist_free(&paths);
	free(cwd);
	return error;
}

__dead static void
usage_revert(void)
{
	fprintf(stderr, "usage: %s revert file-path ...\n", getprogname());
	exit(1);
}

static void
revert_progress(void *arg, unsigned char status, const char *path)
{
	while (path[0] == '/')
		path++;
	printf("%c  %s\n", status, path);
}

static const struct got_error *
cmd_revert(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_worktree *worktree = NULL;
	struct got_repository *repo = NULL;
	char *cwd = NULL, *path = NULL;
	struct got_pathlist_head paths;
	struct got_pathlist_entry *pe;
	int ch, i;

	TAILQ_INIT(&paths);

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			usage_revert();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage_revert();

	for (i = 0; i < argc; i++) {
		char *path = realpath(argv[i], NULL);
		if (path == NULL) {
			error = got_error_from_errno2("realpath", argv[i]);
			goto done;
		}

		got_path_strip_trailing_slashes(path);
		error = got_pathlist_insert(&pe, &paths, path, NULL);
		if (error) {
			free(path);
			goto done;
		}
	}

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}
	error = got_worktree_open(&worktree, cwd);
	if (error)
		goto done;

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree));
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 1,
	    got_worktree_get_root_path(worktree), 0);
	if (error)
		goto done;

	error = got_worktree_revert(worktree, &paths,
	    revert_progress, NULL, repo);
	if (error)
		goto done;
done:
	if (repo)
		got_repo_close(repo);
	if (worktree)
		got_worktree_close(worktree);
	free(path);
	free(cwd);
	return error;
}

__dead static void
usage_commit(void)
{
	fprintf(stderr, "usage: %s commit [-m msg] file-path\n", getprogname());
	exit(1);
}

int
spawn_editor(const char *editor, const char *file)
{
	pid_t pid;
	sig_t sighup, sigint, sigquit;
	int st = -1;

	sighup = signal(SIGHUP, SIG_IGN);
	sigint = signal(SIGINT, SIG_IGN);
	sigquit = signal(SIGQUIT, SIG_IGN);

	switch (pid = fork()) {
	case -1:
		goto doneediting;
	case 0:
		execl(editor, editor, file, (char *)NULL);
		_exit(127);
	}

	while (waitpid(pid, &st, 0) == -1)
		if (errno != EINTR)
			break;

doneediting:
	(void)signal(SIGHUP, sighup);
	(void)signal(SIGINT, sigint);
	(void)signal(SIGQUIT, sigquit);

	if (!WIFEXITED(st)) {
		errno = EINTR;
		return -1;
	}

	return WEXITSTATUS(st);
}

struct collect_commit_logmsg_arg {
	const char *cmdline_log;
	const char *editor;
	const char *worktree_path;
	const char *branch_name;
	const char *repo_path;
	char *logmsg_path;

};

static const struct got_error *
collect_commit_logmsg(struct got_pathlist_head *commitable_paths, char **logmsg,
    void *arg)
{
	char *initial_content = NULL;
	struct got_pathlist_entry *pe;
	const struct got_error *err = NULL;
	char *template = NULL;
	struct collect_commit_logmsg_arg *a = arg;
	char buf[1024];
	struct stat st, st2;
	FILE *fp;
	size_t len;
	int fd, content_changed = 0;

	/* if a message was specified on the command line, just use it */
	if (a->cmdline_log != NULL && strlen(a->cmdline_log) != 0) {
		len = strlen(a->cmdline_log) + 1;
		*logmsg = malloc(len + 1);
		if (*logmsg == NULL)
			return got_error_from_errno("malloc");
		strlcpy(*logmsg, a->cmdline_log, len);
		return NULL;
	}

	if (asprintf(&template, "%s/logmsg", a->worktree_path) == -1)
		return got_error_from_errno("asprintf");

	if (asprintf(&initial_content,
	    "\n# changes to be committed on branch %s:\n",
	    a->branch_name) == -1)
		return got_error_from_errno("asprintf");

	err = got_opentemp_named_fd(&a->logmsg_path, &fd, template);
	if (err)
		goto done;

	dprintf(fd, initial_content);

	TAILQ_FOREACH(pe, commitable_paths, entry) {
		struct got_commitable *ct = pe->data;
		dprintf(fd, "#  %c  %s\n",
		    got_commitable_get_status(ct),
		    got_commitable_get_path(ct));
	}
	close(fd);

	if (stat(a->logmsg_path, &st) == -1) {
		err = got_error_from_errno2("stat", a->logmsg_path);
		goto done;
	}

	if (spawn_editor(a->editor, a->logmsg_path) == -1) {
		err = got_error_from_errno("failed spawning editor");
		goto done;
	}

	if (stat(a->logmsg_path, &st2) == -1) {
		err = got_error_from_errno("stat");
		goto done;
	}

	if (st.st_mtime == st2.st_mtime && st.st_size == st2.st_size) {
		unlink(a->logmsg_path);
		free(a->logmsg_path);
		a->logmsg_path = NULL;
		err = got_error_msg(GOT_ERR_COMMIT_MSG_EMPTY,
		    "no changes made to commit message, aborting");
		goto done;
	}

	*logmsg = malloc(st2.st_size + 1);
	if (*logmsg == NULL) {
		err = got_error_from_errno("malloc");
		goto done;
	}
	(*logmsg)[0] = '\0';
	len = 0;

	fp = fopen(a->logmsg_path, "r");
	if (fp == NULL) {
		err = got_error_from_errno("fopen");
		goto done;
	}
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		if (!content_changed && strcmp(buf, initial_content) != 0)
			content_changed = 1;
		if (buf[0] == '#' || (len == 0 && buf[0] == '\n'))
			continue; /* remove comments and leading empty lines */
		len = strlcat(*logmsg, buf, st2.st_size);
	}
	fclose(fp);

	while (len > 0 && (*logmsg)[len - 1] == '\n') {
		(*logmsg)[len - 1] = '\0';
		len--;
	}

	if (len == 0 || !content_changed) {
		unlink(a->logmsg_path);
		free(a->logmsg_path);
		a->logmsg_path = NULL;
		err = got_error_msg(GOT_ERR_COMMIT_MSG_EMPTY,
		    "commit message cannot be empty, aborting");
		goto done;
	}
done:
	free(initial_content);
	free(template);

	/* Editor is done; we can now apply unveil(2) */
	if (err == NULL)
		err = apply_unveil(a->repo_path, 0, a->worktree_path, 0);
	return err;
}

static const struct got_error *
cmd_commit(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_worktree *worktree = NULL;
	struct got_repository *repo = NULL;
	char *cwd = NULL, *path = NULL, *id_str = NULL;
	struct got_object_id *id = NULL;
	const char *logmsg = NULL;
	const char *got_author = getenv("GOT_AUTHOR");
	struct collect_commit_logmsg_arg cl_arg;
	char *editor = NULL;
	int ch;

	while ((ch = getopt(argc, argv, "m:")) != -1) {
		switch (ch) {
		case 'm':
			logmsg = optarg;
			break;
		default:
			usage_commit();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 1) {
		path = realpath(argv[0], NULL);
		if (path == NULL) {
			error = got_error_from_errno2("realpath", argv[0]);
			goto done;
		}
		got_path_strip_trailing_slashes(path);
	} else if (argc != 0)
		usage_commit();

	if (got_author == NULL) {
		/* TODO: Look current user up in password database */
		error = got_error(GOT_ERR_COMMIT_NO_AUTHOR);
		goto done;
	}

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}
	error = got_worktree_open(&worktree, cwd);
	if (error)
		goto done;

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree));
	if (error != NULL)
		goto done;

	/*
	 * unveil(2) traverses exec(2); if an editor is used we have
	 * to apply unveil after the log message has been written.
	 */
	if (logmsg == NULL || strlen(logmsg) == 0)
		error = get_editor(&editor);
	else
		error = apply_unveil(got_repo_get_path(repo), 0,
		    got_worktree_get_root_path(worktree), 0);
	if (error)
		goto done;

	cl_arg.editor = editor;
	cl_arg.cmdline_log = logmsg;
	cl_arg.worktree_path = got_worktree_get_root_path(worktree);
	cl_arg.branch_name = got_worktree_get_head_ref_name(worktree);
	if (strncmp(cl_arg.branch_name, "refs/", 5) == 0)
		cl_arg.branch_name += 5;
	if (strncmp(cl_arg.branch_name, "heads/", 6) == 0)
		cl_arg.branch_name += 6;
	cl_arg.repo_path = got_repo_get_path(repo);
	cl_arg.logmsg_path = NULL;
	error = got_worktree_commit(&id, worktree, path, got_author, NULL,
	    collect_commit_logmsg, &cl_arg, print_status, NULL, repo);
	if (error) {
		if (cl_arg.logmsg_path)
			fprintf(stderr, "%s: log message preserved in %s\n",
			    getprogname(), cl_arg.logmsg_path);
		goto done;
	}

	if (cl_arg.logmsg_path)
		unlink(cl_arg.logmsg_path);

	error = got_object_id_str(&id_str, id);
	if (error)
		goto done;
	printf("Created commit %s\n", id_str);
done:
	if (repo)
		got_repo_close(repo);
	if (worktree)
		got_worktree_close(worktree);
	free(path);
	free(cwd);
	free(id_str);
	free(editor);
	return error;
}

__dead static void
usage_cherrypick(void)
{
	fprintf(stderr, "usage: %s cherrypick commit-id\n", getprogname());
	exit(1);
}

static const struct got_error *
cmd_cherrypick(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_worktree *worktree = NULL;
	struct got_repository *repo = NULL;
	char *cwd = NULL, *commit_id_str = NULL;
	struct got_object_id *commit_id = NULL;
	struct got_commit_object *commit = NULL;
	struct got_object_qid *pid;
	struct got_reference *head_ref = NULL;
	int ch, did_something = 0;

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			usage_cherrypick();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage_cherrypick();

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}
	error = got_worktree_open(&worktree, cwd);
	if (error)
		goto done;

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree));
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 0,
	    got_worktree_get_root_path(worktree), 0);
	if (error)
		goto done;

	error = got_repo_match_object_id_prefix(&commit_id, argv[0],
	    GOT_OBJ_TYPE_COMMIT, repo);
	if (error != NULL) {
		struct got_reference *ref;
		if (error->code != GOT_ERR_BAD_OBJ_ID_STR)
			goto done;
		error = got_ref_open(&ref, repo, argv[0], 0);
		if (error != NULL)
			goto done;
		error = got_ref_resolve(&commit_id, repo, ref);
		got_ref_close(ref);
		if (error != NULL)
			goto done;
	}
	error = got_object_id_str(&commit_id_str, commit_id);
	if (error)
		goto done;

	error = got_ref_open(&head_ref, repo,
	    got_worktree_get_head_ref_name(worktree), 0);
	if (error != NULL)
		goto done;

	error = check_same_branch(commit_id, head_ref, repo);
	if (error) {
		if (error->code != GOT_ERR_ANCESTRY)
			goto done;
		error = NULL;
	} else {
		error = got_error(GOT_ERR_SAME_BRANCH);
		goto done;
	}

	error = got_object_open_as_commit(&commit, repo, commit_id);
	if (error)
		goto done;
	pid = SIMPLEQ_FIRST(got_object_commit_get_parent_ids(commit));
	error = got_worktree_merge_files(worktree, pid ? pid->id : NULL,
	    commit_id, repo, update_progress, &did_something, check_cancelled,
	    NULL);
	if (error != NULL)
		goto done;

	if (did_something)
		printf("Merged commit %s\n", commit_id_str);
done:
	if (commit)
		got_object_commit_close(commit);
	free(commit_id_str);
	if (head_ref)
		got_ref_close(head_ref);
	if (worktree)
		got_worktree_close(worktree);
	if (repo)
		got_repo_close(repo);
	return error;
}

__dead static void
usage_backout(void)
{
	fprintf(stderr, "usage: %s backout commit-id\n", getprogname());
	exit(1);
}

static const struct got_error *
cmd_backout(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_worktree *worktree = NULL;
	struct got_repository *repo = NULL;
	char *cwd = NULL, *commit_id_str = NULL;
	struct got_object_id *commit_id = NULL;
	struct got_commit_object *commit = NULL;
	struct got_object_qid *pid;
	struct got_reference *head_ref = NULL;
	int ch, did_something = 0;

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			usage_backout();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage_backout();

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}
	error = got_worktree_open(&worktree, cwd);
	if (error)
		goto done;

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree));
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 0,
	    got_worktree_get_root_path(worktree), 0);
	if (error)
		goto done;

	error = got_repo_match_object_id_prefix(&commit_id, argv[0],
	    GOT_OBJ_TYPE_COMMIT, repo);
	if (error != NULL) {
		struct got_reference *ref;
		if (error->code != GOT_ERR_BAD_OBJ_ID_STR)
			goto done;
		error = got_ref_open(&ref, repo, argv[0], 0);
		if (error != NULL)
			goto done;
		error = got_ref_resolve(&commit_id, repo, ref);
		got_ref_close(ref);
		if (error != NULL)
			goto done;
	}
	error = got_object_id_str(&commit_id_str, commit_id);
	if (error)
		goto done;

	error = got_ref_open(&head_ref, repo,
	    got_worktree_get_head_ref_name(worktree), 0);
	if (error != NULL)
		goto done;

	error = check_same_branch(commit_id, head_ref, repo);
	if (error)
		goto done;

	error = got_object_open_as_commit(&commit, repo, commit_id);
	if (error)
		goto done;
	pid = SIMPLEQ_FIRST(got_object_commit_get_parent_ids(commit));
	if (pid == NULL) {
		error = got_error(GOT_ERR_ROOT_COMMIT);
		goto done;
	}

	error = got_worktree_merge_files(worktree, commit_id, pid->id, repo,
	    update_progress, &did_something, check_cancelled, NULL);
	if (error != NULL)
		goto done;

	if (did_something)
		printf("Backed out commit %s\n", commit_id_str);
done:
	if (commit)
		got_object_commit_close(commit);
	free(commit_id_str);
	if (head_ref)
		got_ref_close(head_ref);
	if (worktree)
		got_worktree_close(worktree);
	if (repo)
		got_repo_close(repo);
	return error;
}

__dead static void
usage_rebase(void)
{
	fprintf(stderr, "usage: %s rebase [-a] [-c] | branch\n", getprogname());
	exit(1);
}

static const struct got_error *
show_rebase_progress(struct got_commit_object *commit,
    struct got_object_id *old_id, struct got_object_id *new_id)
{
	const struct got_error *err;
	char *old_id_str = NULL, *new_id_str = NULL;
	char *logmsg0 = NULL, *logmsg, *nl;
	size_t len;

	err = got_object_id_str(&old_id_str, old_id);
	if (err)
		goto done;

	if (new_id) {
		err = got_object_id_str(&new_id_str, new_id);
		if (err)
			goto done;
	}

	logmsg0 = strdup(got_object_commit_get_logmsg(commit));
	if (logmsg0 == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}
	logmsg = logmsg0;

	while (isspace(logmsg[0]))
		logmsg++;

	old_id_str[12] = '\0';
	if (new_id_str)
		new_id_str[12] = '\0';
	len = strlen(logmsg);
	if (len > 42)
		len = 42;
	logmsg[len] = '\0';
	nl = strchr(logmsg, '\n');
	if (nl)
		*nl = '\0';
	printf("%s -> %s: %s\n", old_id_str,
	    new_id_str ? new_id_str : "no-op change", logmsg);
done:
	free(old_id_str);
	free(new_id_str);
	free(logmsg0);
	return err;
}

static void
rebase_progress(void *arg, unsigned char status, const char *path)
{
	unsigned char *rebase_status = arg;

	while (path[0] == '/')
		path++;
	printf("%c  %s\n", status, path);

	if (*rebase_status == GOT_STATUS_CONFLICT)
		return;
	if (status == GOT_STATUS_CONFLICT || status == GOT_STATUS_MERGE)
		*rebase_status = status;
}

static const struct got_error *
rebase_complete(struct got_worktree *worktree, struct got_reference *branch,
    struct got_reference *new_base_branch, struct got_reference *tmp_branch,
    struct got_repository *repo)
{
	printf("Switching work tree to %s\n", got_ref_get_name(branch));
	return got_worktree_rebase_complete(worktree,
	    new_base_branch, tmp_branch, branch, repo);
}

static const struct got_error *
rebase_commit(struct got_worktree *worktree, struct got_reference *tmp_branch,
   struct got_object_id *commit_id, struct got_repository *repo)
{
	const struct got_error *error;
	struct got_commit_object *commit;
	struct got_object_id *new_commit_id;

	error = got_object_open_as_commit(&commit, repo, commit_id);
	if (error)
		return error;

	error = got_worktree_rebase_commit(&new_commit_id, worktree,
	    tmp_branch, commit, commit_id, repo);
	if (error) {
		if (error->code != GOT_ERR_COMMIT_NO_CHANGES)
			goto done;
		error = show_rebase_progress(commit, commit_id, NULL);
	} else {
		error = show_rebase_progress(commit, commit_id, new_commit_id);
		free(new_commit_id);
	}
done:
	got_object_commit_close(commit);
	return error;
}

static const struct got_error *
cmd_rebase(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_worktree *worktree = NULL;
	struct got_repository *repo = NULL;
	char *cwd = NULL;
	struct got_reference *branch = NULL;
	struct got_reference *new_base_branch = NULL, *tmp_branch = NULL;
	struct got_object_id *commit_id = NULL, *parent_id = NULL;
	struct got_object_id *resume_commit_id = NULL;
	struct got_object_id *branch_head_commit_id = NULL, *yca_id = NULL;
	struct got_commit_graph *graph = NULL;
	struct got_commit_object *commit = NULL;
	int ch, rebase_in_progress = 0, abort_rebase = 0, continue_rebase = 0;
	unsigned char rebase_status = GOT_STATUS_NO_CHANGE;
	struct got_object_id_queue commits;
	const struct got_object_id_queue *parent_ids;
	struct got_object_qid *qid, *pid;

	SIMPLEQ_INIT(&commits);

	while ((ch = getopt(argc, argv, "ac")) != -1) {
		switch (ch) {
		case 'a':
			abort_rebase = 1;
			break;
		case 'c':
			continue_rebase = 1;
			break;
		default:
			usage_rebase();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (abort_rebase && continue_rebase)
		usage_rebase();
	else if (abort_rebase || continue_rebase) {
		if (argc != 0)
			usage_rebase();
	} else if (argc != 1)
		usage_rebase();

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}
	error = got_worktree_open(&worktree, cwd);
	if (error)
		goto done;


	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree));
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 0,
	    got_worktree_get_root_path(worktree), 0);
	if (error)
		goto done;

	error = got_worktree_rebase_in_progress(&rebase_in_progress, worktree);
	if (error)
		goto done;

	if (rebase_in_progress && abort_rebase) {
		int did_something;
		error = got_worktree_rebase_continue(&resume_commit_id,
		    &new_base_branch, &tmp_branch, &branch, worktree, repo);
		if (error)
			goto done;
		printf("Switching work tree to %s\n",
		    got_ref_get_symref_target(new_base_branch));
		error = got_worktree_rebase_abort(worktree, repo,
		    new_base_branch, update_progress, &did_something);
		if (error)
			goto done;
		printf("Rebase of %s aborted\n", got_ref_get_name(branch));
		goto done; /* nothing else to do */
	} else if (abort_rebase) {
		error = got_error(GOT_ERR_NOT_REBASING);
		goto done;
	}

	if (continue_rebase) {
		error = got_worktree_rebase_continue(&resume_commit_id,
		    &new_base_branch, &tmp_branch, &branch, worktree, repo);
		if (error)
			goto done;

		error = rebase_commit(worktree, tmp_branch, resume_commit_id,
		    repo);
		if (error)
			goto done;

		yca_id = got_object_id_dup(resume_commit_id);
		if (yca_id == NULL) {
			error = got_error_from_errno("got_object_id_dup");
			goto done;
		}
	} else {
		error = got_ref_open(&branch, repo, argv[0], 0);
		if (error != NULL)
			goto done;

		error = check_same_branch(
		    got_worktree_get_base_commit_id(worktree), branch, repo);
		if (error) {
			if (error->code != GOT_ERR_ANCESTRY)
				goto done;
			error = NULL;
		} else {
			error = got_error_msg(GOT_ERR_SAME_BRANCH,
			    "specified branch resolves to a commit which "
			    "is already contained in work tree's branch");
			goto done;
		}
	}

	error = got_ref_resolve(&branch_head_commit_id, repo, branch);
	if (error)
		goto done;

	if (!continue_rebase) {
		error = got_commit_graph_find_youngest_common_ancestor(&yca_id,
		    got_worktree_get_base_commit_id(worktree),
		    branch_head_commit_id, repo);
		if (error)
			goto done;
		if (yca_id == NULL) {
			error = got_error_msg(GOT_ERR_ANCESTRY,
			    "specified branch shares no common ancestry "
			    "with work tree's branch");
			goto done;
		}

		error = got_worktree_rebase_prepare(&new_base_branch,
		    &tmp_branch, worktree, branch, repo);
		if (error)
			goto done;
	}

	commit_id = branch_head_commit_id;
	error = got_object_open_as_commit(&commit, repo, commit_id);
	if (error)
		goto done;

	error = got_commit_graph_open(&graph, commit_id, "/", 1, repo);
	if (error)
		goto done;
	parent_ids = got_object_commit_get_parent_ids(commit);
	pid = SIMPLEQ_FIRST(parent_ids);
	error = got_commit_graph_iter_start(graph, pid->id, repo);
	got_object_commit_close(commit);
	commit = NULL;
	if (error)
		goto done;
	while (got_object_id_cmp(commit_id, yca_id) != 0) {
		error = got_commit_graph_iter_next(&parent_id, graph);
		if (error) {
			if (error->code == GOT_ERR_ITER_COMPLETED) {
				error = got_error_msg(GOT_ERR_ANCESTRY,
				    "ran out of commits to rebase before "
				    "youngest common ancestor commit has "
				    "been reached?!?");
				goto done;
			} else if (error->code != GOT_ERR_ITER_NEED_MORE)
				goto done;
			error = got_commit_graph_fetch_commits(graph, 1, repo);
			if (error)
				goto done;
		} else {
			error = got_object_qid_alloc(&qid, commit_id);
			if (error)
				goto done;
			SIMPLEQ_INSERT_HEAD(&commits, qid, entry);
			commit_id = parent_id;
		}
	}

	if (SIMPLEQ_EMPTY(&commits)) {
		if (continue_rebase)
			error = rebase_complete(worktree, branch,
			    new_base_branch, tmp_branch, repo);
		else
			error = got_error(GOT_ERR_EMPTY_REBASE);
		goto done;
	}

	pid = NULL;
	SIMPLEQ_FOREACH(qid, &commits, entry) {
		commit_id = qid->id;
		parent_id = pid ? pid->id : yca_id;
		pid = qid;

		error = got_worktree_rebase_merge_files(worktree, parent_id,
		    commit_id, repo, rebase_progress, &rebase_status,
		    check_cancelled, NULL);
		if (error)
			goto done;

		if (rebase_status == GOT_STATUS_CONFLICT)
			break;

		error = rebase_commit(worktree, tmp_branch, commit_id, repo);
		if (error)
			goto done;
	}

	if (rebase_status == GOT_STATUS_CONFLICT) {
		error = got_worktree_rebase_postpone(worktree);
		if (error)
			goto done;
		error = got_error_msg(GOT_ERR_CONFLICTS,
		    "conflicts must be resolved before rebase can be resumed");
	} else
		error = rebase_complete(worktree, branch, new_base_branch,
		    tmp_branch, repo);
done:
	got_object_id_queue_free(&commits);
	free(branch_head_commit_id);
	free(resume_commit_id);
	free(yca_id);
	if (graph)
		got_commit_graph_close(graph);
	if (commit)
		got_object_commit_close(commit);
	if (branch)
		got_ref_close(branch);
	if (new_base_branch)
		got_ref_close(new_base_branch);
	if (tmp_branch)
		got_ref_close(tmp_branch);
	if (worktree)
		got_worktree_close(worktree);
	if (repo)
		got_repo_close(repo);
	return error;
}
