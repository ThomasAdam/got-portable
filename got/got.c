/*
 * Copyright (c) 2017 Martin Pieuchot <mpi@openbsd.org>
 * Copyright (c) 2018, 2019, 2020 Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2020 Ori Bernstein <ori@openbsd.org>
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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/wait.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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
#include <regex.h>
#include <getopt.h>
#include <util.h>

#include "got_version.h"
#include "got_error.h"
#include "got_object.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_path.h"
#include "got_cancel.h"
#include "got_worktree.h"
#include "got_diff.h"
#include "got_commit_graph.h"
#include "got_fetch.h"
#include "got_blame.h"
#include "got_privsep.h"
#include "got_opentemp.h"
#include "got_gotconfig.h"

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
	const char	*cmd_name;
	const struct got_error *(*cmd_main)(int, char *[]);
	void		(*cmd_usage)(void);
	const char	*cmd_alias;
};

__dead static void	usage(int, int);
__dead static void	usage_init(void);
__dead static void	usage_import(void);
__dead static void	usage_clone(void);
__dead static void	usage_fetch(void);
__dead static void	usage_checkout(void);
__dead static void	usage_update(void);
__dead static void	usage_log(void);
__dead static void	usage_diff(void);
__dead static void	usage_blame(void);
__dead static void	usage_tree(void);
__dead static void	usage_status(void);
__dead static void	usage_ref(void);
__dead static void	usage_branch(void);
__dead static void	usage_tag(void);
__dead static void	usage_add(void);
__dead static void	usage_remove(void);
__dead static void	usage_revert(void);
__dead static void	usage_commit(void);
__dead static void	usage_cherrypick(void);
__dead static void	usage_backout(void);
__dead static void	usage_rebase(void);
__dead static void	usage_histedit(void);
__dead static void	usage_integrate(void);
__dead static void	usage_stage(void);
__dead static void	usage_unstage(void);
__dead static void	usage_cat(void);
__dead static void	usage_info(void);

static const struct got_error*		cmd_init(int, char *[]);
static const struct got_error*		cmd_import(int, char *[]);
static const struct got_error*		cmd_clone(int, char *[]);
static const struct got_error*		cmd_fetch(int, char *[]);
static const struct got_error*		cmd_checkout(int, char *[]);
static const struct got_error*		cmd_update(int, char *[]);
static const struct got_error*		cmd_log(int, char *[]);
static const struct got_error*		cmd_diff(int, char *[]);
static const struct got_error*		cmd_blame(int, char *[]);
static const struct got_error*		cmd_tree(int, char *[]);
static const struct got_error*		cmd_status(int, char *[]);
static const struct got_error*		cmd_ref(int, char *[]);
static const struct got_error*		cmd_branch(int, char *[]);
static const struct got_error*		cmd_tag(int, char *[]);
static const struct got_error*		cmd_add(int, char *[]);
static const struct got_error*		cmd_remove(int, char *[]);
static const struct got_error*		cmd_revert(int, char *[]);
static const struct got_error*		cmd_commit(int, char *[]);
static const struct got_error*		cmd_cherrypick(int, char *[]);
static const struct got_error*		cmd_backout(int, char *[]);
static const struct got_error*		cmd_rebase(int, char *[]);
static const struct got_error*		cmd_histedit(int, char *[]);
static const struct got_error*		cmd_integrate(int, char *[]);
static const struct got_error*		cmd_stage(int, char *[]);
static const struct got_error*		cmd_unstage(int, char *[]);
static const struct got_error*		cmd_cat(int, char *[]);
static const struct got_error*		cmd_info(int, char *[]);

static struct got_cmd got_commands[] = {
	{ "init",	cmd_init,	usage_init,	"" },
	{ "import",	cmd_import,	usage_import,	"im" },
	{ "clone",	cmd_clone,	usage_clone,	"cl" },
	{ "fetch",	cmd_fetch,	usage_fetch,	"fe" },
	{ "checkout",	cmd_checkout,	usage_checkout,	"co" },
	{ "update",	cmd_update,	usage_update,	"up" },
	{ "log",	cmd_log,	usage_log,	"" },
	{ "diff",	cmd_diff,	usage_diff,	"di" },
	{ "blame",	cmd_blame,	usage_blame,	"bl" },
	{ "tree",	cmd_tree,	usage_tree,	"tr" },
	{ "status",	cmd_status,	usage_status,	"st" },
	{ "ref",	cmd_ref,	usage_ref,	"" },
	{ "branch",	cmd_branch,	usage_branch,	"br" },
	{ "tag",	cmd_tag,	usage_tag,	"" },
	{ "add",	cmd_add,	usage_add,	"" },
	{ "remove",	cmd_remove,	usage_remove,	"rm" },
	{ "revert",	cmd_revert,	usage_revert,	"rv" },
	{ "commit",	cmd_commit,	usage_commit,	"ci" },
	{ "cherrypick",	cmd_cherrypick,	usage_cherrypick, "cy" },
	{ "backout",	cmd_backout,	usage_backout,	"bo" },
	{ "rebase",	cmd_rebase,	usage_rebase,	"rb" },
	{ "histedit",	cmd_histedit,	usage_histedit,	"he" },
	{ "integrate",  cmd_integrate,  usage_integrate,"ig" },
	{ "stage",	cmd_stage,	usage_stage,	"sg" },
	{ "unstage",	cmd_unstage,	usage_unstage,	"ug" },
	{ "cat",	cmd_cat,	usage_cat,	"" },
	{ "info",	cmd_info,	usage_info,	"" },
};

static void
list_commands(FILE *fp)
{
	size_t i;

	fprintf(fp, "commands:");
	for (i = 0; i < nitems(got_commands); i++) {
		struct got_cmd *cmd = &got_commands[i];
		fprintf(fp, " %s", cmd->cmd_name);
	}
	fputc('\n', fp);
}

__dead static void
option_conflict(char a, char b)
{
	errx(1, "-%c and -%c options are mutually exclusive", a, b);
}

int
main(int argc, char *argv[])
{
	struct got_cmd *cmd;
	size_t i;
	int ch;
	int hflag = 0, Vflag = 0;
	static struct option longopts[] = {
	    { "version", no_argument, NULL, 'V' },
	    { NULL, 0, NULL, 0 }
	};

	setlocale(LC_CTYPE, "");

	while ((ch = getopt_long(argc, argv, "+hV", longopts, NULL)) != -1) {
		switch (ch) {
		case 'h':
			hflag = 1;
			break;
		case 'V':
			Vflag = 1;
			break;
		default:
			usage(hflag, 1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;
	optind = 1;
	optreset = 1;

	if (Vflag) {
		got_version_print_str();
		return 0;
	}

	if (argc <= 0)
		usage(hflag, hflag ? 0 : 1);

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
		if (error && error->code != GOT_ERR_CANCELLED &&
		    error->code != GOT_ERR_PRIVSEP_EXIT &&
		    !(sigpipe_received &&
		      error->code == GOT_ERR_ERRNO && errno == EPIPE) &&
		    !(sigint_received &&
		      error->code == GOT_ERR_ERRNO && errno == EINTR)) {
			fprintf(stderr, "%s: %s\n", getprogname(), error->msg);
			return 1;
		}

		return 0;
	}

	fprintf(stderr, "%s: unknown command '%s'\n", getprogname(), argv[0]);
	list_commands(stderr);
	return 1;
}

__dead static void
usage(int hflag, int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;

	fprintf(fp, "usage: %s [-h] [-V | --version] command [arg ...]\n",
	    getprogname());
	if (hflag)
		list_commands(fp);
	exit(status);
}

static const struct got_error *
get_editor(char **abspath)
{
	const struct got_error *err = NULL;
	const char *editor;

	*abspath = NULL;

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
    const char *worktree_path)
{
	const struct got_error *err;

#ifdef PROFILE
	if (unveil("gmon.out", "rwc") != 0)
		return got_error_from_errno2("unveil", "gmon.out");
#endif
	if (repo_path && unveil(repo_path, repo_read_only ? "r" : "rwc") != 0)
		return got_error_from_errno2("unveil", repo_path);

	if (worktree_path && unveil(worktree_path, "rwc") != 0)
		return got_error_from_errno2("unveil", worktree_path);

	if (unveil(GOT_TMPDIR_STR, "rwc") != 0)
		return got_error_from_errno2("unveil", GOT_TMPDIR_STR);

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
	fprintf(stderr, "usage: %s init repository-path\n", getprogname());
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

	error = apply_unveil(repo_path, 0, NULL);
	if (error)
		goto done;

	error = got_repo_init(repo_path);
done:
	free(repo_path);
	return error;
}

__dead static void
usage_import(void)
{
	fprintf(stderr, "usage: %s import [-b branch] [-m message] "
	    "[-r repository-path] [-I pattern] path\n", getprogname());
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

static const struct got_error *
edit_logmsg(char **logmsg, const char *editor, const char *logmsg_path,
    const char *initial_content, size_t initial_content_len, int check_comments)
{
	const struct got_error *err = NULL;
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;
	struct stat st, st2;
	FILE *fp = NULL;
	size_t len, logmsg_len;
	char *initial_content_stripped = NULL, *buf = NULL, *s;

	*logmsg = NULL;

	if (stat(logmsg_path, &st) == -1)
		return got_error_from_errno2("stat", logmsg_path);

	if (spawn_editor(editor, logmsg_path) == -1)
		return got_error_from_errno("failed spawning editor");

	if (stat(logmsg_path, &st2) == -1)
		return got_error_from_errno("stat");

	if (st.st_mtime == st2.st_mtime && st.st_size == st2.st_size)
		return got_error_msg(GOT_ERR_COMMIT_MSG_EMPTY,
		    "no changes made to commit message, aborting");

	/*
	 * Set up a stripped version of the initial content without comments
	 * and blank lines. We need this in order to check if the message
	 * has in fact been edited.
	 */
	initial_content_stripped = malloc(initial_content_len + 1);
	if (initial_content_stripped == NULL)
		return got_error_from_errno("malloc");
	initial_content_stripped[0] = '\0';

	buf = strdup(initial_content);
	if (buf == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}
	s = buf;
	len = 0;
	while ((line = strsep(&s, "\n")) != NULL) {
		if ((line[0] == '#' || (len == 0 && line[0] == '\n')))
			continue; /* remove comments and leading empty lines */
		len = strlcat(initial_content_stripped, line,
		    initial_content_len + 1);
		if (len >= initial_content_len + 1) {
			err = got_error(GOT_ERR_NO_SPACE);
			goto done;
		}
	}
	while (len > 0 && initial_content_stripped[len - 1] == '\n') {
		initial_content_stripped[len - 1] = '\0';
		len--;
	}

	logmsg_len = st2.st_size;
	*logmsg = malloc(logmsg_len + 1);
	if (*logmsg == NULL)
		return got_error_from_errno("malloc");
	(*logmsg)[0] = '\0';

	fp = fopen(logmsg_path, "r");
	if (fp == NULL) {
		err = got_error_from_errno("fopen");
		goto done;
	}

	len = 0;
	while ((linelen = getline(&line, &linesize, fp)) != -1) {
		if ((line[0] == '#' || (len == 0 && line[0] == '\n')))
			continue; /* remove comments and leading empty lines */
		len = strlcat(*logmsg, line, logmsg_len + 1);
		if (len >= logmsg_len + 1) {
			err = got_error(GOT_ERR_NO_SPACE);
			goto done;
		}
	}
	free(line);
	if (ferror(fp)) {
		err = got_ferror(fp, GOT_ERR_IO);
		goto done;
	}
	while (len > 0 && (*logmsg)[len - 1] == '\n') {
		(*logmsg)[len - 1] = '\0';
		len--;
	}

	if (len == 0) {
		err = got_error_msg(GOT_ERR_COMMIT_MSG_EMPTY,
		    "commit message cannot be empty, aborting");
		goto done;
	}
	if (check_comments && strcmp(*logmsg, initial_content_stripped) == 0)
		err = got_error_msg(GOT_ERR_COMMIT_MSG_EMPTY,
		    "no changes made to commit message, aborting");
done:
	free(initial_content_stripped);
	free(buf);
	if (fp && fclose(fp) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (err) {
		free(*logmsg);
		*logmsg = NULL;
	}
	return err;
}

static const struct got_error *
collect_import_msg(char **logmsg, char **logmsg_path, const char *editor,
    const char *path_dir, const char *branch_name)
{
	char *initial_content = NULL;
	const struct got_error *err = NULL;
	int initial_content_len;
	int fd = -1;

	initial_content_len = asprintf(&initial_content,
	    "\n# %s to be imported to branch %s\n", path_dir,
	    branch_name);
	if (initial_content_len == -1)
		return got_error_from_errno("asprintf");

	err = got_opentemp_named_fd(logmsg_path, &fd,
	    GOT_TMPDIR_STR "/got-importmsg");
	if (err)
		goto done;

	if (write(fd, initial_content, initial_content_len) == -1) {
		err = got_error_from_errno2("write", *logmsg_path);
		goto done;
	}

	err = edit_logmsg(logmsg, editor, *logmsg_path, initial_content,
	    initial_content_len, 1);
done:
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno2("close", *logmsg_path);
	free(initial_content);
	if (err) {
		free(*logmsg_path);
		*logmsg_path = NULL;
	}
	return err;
}

static const struct got_error *
import_progress(void *arg, const char *path)
{
	printf("A  %s\n", path);
	return NULL;
}

static const struct got_error *
get_author(char **author, struct got_repository *repo,
    struct got_worktree *worktree)
{
	const struct got_error *err = NULL;
	const char *got_author = NULL, *name, *email;
	const struct got_gotconfig *worktree_conf = NULL, *repo_conf = NULL;

	*author = NULL;

	if (worktree)
		worktree_conf = got_worktree_get_gotconfig(worktree);
	repo_conf = got_repo_get_gotconfig(repo);

	/*
	 * Priority of potential author information sources, from most
	 * significant to least significant:
	 * 1) work tree's .got/got.conf file
	 * 2) repository's got.conf file
	 * 3) repository's git config file
	 * 4) environment variables
	 * 5) global git config files (in user's home directory or /etc)
	 */

	if (worktree_conf)
		got_author = got_gotconfig_get_author(worktree_conf);
	if (got_author == NULL)
		got_author = got_gotconfig_get_author(repo_conf);
	if (got_author == NULL) {
		name = got_repo_get_gitconfig_author_name(repo);
		email = got_repo_get_gitconfig_author_email(repo);
		if (name && email) {
			if (asprintf(author, "%s <%s>", name, email) == -1)
				return got_error_from_errno("asprintf");
			return NULL;
		}

		got_author = getenv("GOT_AUTHOR");
		if (got_author == NULL) {
			name = got_repo_get_global_gitconfig_author_name(repo);
			email = got_repo_get_global_gitconfig_author_email(
			    repo);
			if (name && email) {
				if (asprintf(author, "%s <%s>", name, email)
				    == -1)
					return got_error_from_errno("asprintf");
				return NULL;
			}
			/* TODO: Look up user in password database? */
			return got_error(GOT_ERR_COMMIT_NO_AUTHOR);
		}
	}

	*author = strdup(got_author);
	if (*author == NULL)
		return got_error_from_errno("strdup");

	/*
	 * Really dumb email address check; we're only doing this to
	 * avoid git's object parser breaking on commits we create.
	 */
	while (*got_author && *got_author != '<')
		got_author++;
	if (*got_author != '<') {
		err = got_error(GOT_ERR_COMMIT_NO_EMAIL);
		goto done;
	}
	while (*got_author && *got_author != '@')
		got_author++;
	if (*got_author != '@') {
		err = got_error(GOT_ERR_COMMIT_NO_EMAIL);
		goto done;
	}
	while (*got_author && *got_author != '>')
		got_author++;
	if (*got_author != '>')
		err = got_error(GOT_ERR_COMMIT_NO_EMAIL);
done:
	if (err) {
		free(*author);
		*author = NULL;
	}
	return err;
}

static const struct got_error *
get_gitconfig_path(char **gitconfig_path)
{
	const char *homedir = getenv("HOME");

	*gitconfig_path = NULL;
	if (homedir) {
		if (asprintf(gitconfig_path, "%s/.gitconfig", homedir) == -1)
			return got_error_from_errno("asprintf");

	}
	return NULL;
}

static const struct got_error *
cmd_import(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	char *path_dir = NULL, *repo_path = NULL, *logmsg = NULL;
	char *gitconfig_path = NULL, *editor = NULL, *author = NULL;
	const char *branch_name = "main";
	char *refname = NULL, *id_str = NULL, *logmsg_path = NULL;
	struct got_repository *repo = NULL;
	struct got_reference *branch_ref = NULL, *head_ref = NULL;
	struct got_object_id *new_commit_id = NULL;
	int ch;
	struct got_pathlist_head ignores;
	struct got_pathlist_entry *pe;
	int preserve_logmsg = 0;

	TAILQ_INIT(&ignores);

	while ((ch = getopt(argc, argv, "b:m:r:I:")) != -1) {
		switch (ch) {
		case 'b':
			branch_name = optarg;
			break;
		case 'm':
			logmsg = strdup(optarg);
			if (logmsg == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL) {
				error = got_error_from_errno2("realpath",
				    optarg);
				goto done;
			}
			break;
		case 'I':
			if (optarg[0] == '\0')
				break;
			error = got_pathlist_insert(&pe, &ignores, optarg,
			    NULL);
			if (error)
				goto done;
			break;
		default:
			usage_import();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec sendfd "
	    "unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif
	if (argc != 1)
		usage_import();

	if (repo_path == NULL) {
		repo_path = getcwd(NULL, 0);
		if (repo_path == NULL)
			return got_error_from_errno("getcwd");
	}
	got_path_strip_trailing_slashes(repo_path);
	error = get_gitconfig_path(&gitconfig_path);
	if (error)
		goto done;
	error = got_repo_open(&repo, repo_path, gitconfig_path);
	if (error)
		goto done;

	error = get_author(&author, repo, NULL);
	if (error)
		return error;

	/*
	 * Don't let the user create a branch name with a leading '-'.
	 * While technically a valid reference name, this case is usually
	 * an unintended typo.
	 */
	if (branch_name[0] == '-')
		return got_error_path(branch_name, GOT_ERR_REF_NAME_MINUS);

	if (asprintf(&refname, "refs/heads/%s", branch_name) == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}

	error = got_ref_open(&branch_ref, repo, refname, 0);
	if (error) {
		if (error->code != GOT_ERR_NOT_REF)
			goto done;
	} else {
		error = got_error_msg(GOT_ERR_BRANCH_EXISTS,
		    "import target branch already exists");
		goto done;
	}

	path_dir = realpath(argv[0], NULL);
	if (path_dir == NULL) {
		error = got_error_from_errno2("realpath", argv[0]);
		goto done;
	}
	got_path_strip_trailing_slashes(path_dir);

	/*
	 * unveil(2) traverses exec(2); if an editor is used we have
	 * to apply unveil after the log message has been written.
	 */
	if (logmsg == NULL || strlen(logmsg) == 0) {
		error = get_editor(&editor);
		if (error)
			goto done;
		free(logmsg);
		error = collect_import_msg(&logmsg, &logmsg_path, editor,
		    path_dir, refname);
		if (error) {
			if (error->code != GOT_ERR_COMMIT_MSG_EMPTY &&
			    logmsg_path != NULL)
				preserve_logmsg = 1;
			goto done;
		}
	}

	if (unveil(path_dir, "r") != 0) {
		error = got_error_from_errno2("unveil", path_dir);
		if (logmsg_path)
			preserve_logmsg = 1;
		goto done;
	}

	error = apply_unveil(got_repo_get_path(repo), 0, NULL);
	if (error) {
		if (logmsg_path)
			preserve_logmsg = 1;
		goto done;
	}

	error = got_repo_import(&new_commit_id, path_dir, logmsg,
	    author, &ignores, repo, import_progress, NULL);
	if (error) {
		if (logmsg_path)
			preserve_logmsg = 1;
		goto done;
	}

	error = got_ref_alloc(&branch_ref, refname, new_commit_id);
	if (error) {
		if (logmsg_path)
			preserve_logmsg = 1;
		goto done;
	}

	error = got_ref_write(branch_ref, repo);
	if (error) {
		if (logmsg_path)
			preserve_logmsg = 1;
		goto done;
	}

	error = got_object_id_str(&id_str, new_commit_id);
	if (error) {
		if (logmsg_path)
			preserve_logmsg = 1;
		goto done;
	}

	error = got_ref_open(&head_ref, repo, GOT_REF_HEAD, 0);
	if (error) {
		if (error->code != GOT_ERR_NOT_REF) {
			if (logmsg_path)
				preserve_logmsg = 1;
			goto done;
		}

		error = got_ref_alloc_symref(&head_ref, GOT_REF_HEAD,
		    branch_ref);
		if (error) {
			if (logmsg_path)
				preserve_logmsg = 1;
			goto done;
		}

		error = got_ref_write(head_ref, repo);
		if (error) {
			if (logmsg_path)
				preserve_logmsg = 1;
			goto done;
		}
	}

	printf("Created branch %s with commit %s\n",
	    got_ref_get_name(branch_ref), id_str);
done:
	if (preserve_logmsg) {
		fprintf(stderr, "%s: log message preserved in %s\n",
		    getprogname(), logmsg_path);
	} else if (logmsg_path && unlink(logmsg_path) == -1 && error == NULL)
		error = got_error_from_errno2("unlink", logmsg_path);
	free(logmsg);
	free(logmsg_path);
	free(repo_path);
	free(editor);
	free(refname);
	free(new_commit_id);
	free(id_str);
	free(author);
	free(gitconfig_path);
	if (branch_ref)
		got_ref_close(branch_ref);
	if (head_ref)
		got_ref_close(head_ref);
	return error;
}

__dead static void
usage_clone(void)
{
	fprintf(stderr, "usage: %s clone [-a] [-b branch] [-l] [-m] [-q] [-v] "
	    "[-R reference] repository-url [directory]\n", getprogname());
	exit(1);
}

struct got_fetch_progress_arg {
	char last_scaled_size[FMT_SCALED_STRSIZE];
	int last_p_indexed;
	int last_p_resolved;
	int verbosity;

	struct got_repository *repo;

	int create_configs;
	int configs_created;
	struct {
		struct got_pathlist_head *symrefs;
		struct got_pathlist_head *wanted_branches;
		const char *proto;
		const char *host;
		const char *port;
		const char *remote_repo_path;
		const char *git_url;
		int fetch_all_branches;
		int mirror_references;
	} config_info;
};

/* XXX forward declaration */
static const struct got_error *
create_config_files(const char *proto, const char *host, const char *port,
    const char *remote_repo_path, const char *git_url, int fetch_all_branches,
    int mirror_references, struct got_pathlist_head *symrefs,
    struct got_pathlist_head *wanted_branches, struct got_repository *repo);

static const struct got_error *
fetch_progress(void *arg, const char *message, off_t packfile_size,
    int nobj_total, int nobj_indexed, int nobj_loose, int nobj_resolved)
{
	const struct got_error *err = NULL;
	struct got_fetch_progress_arg *a = arg;
	char scaled_size[FMT_SCALED_STRSIZE];
	int p_indexed, p_resolved;
	int print_size = 0, print_indexed = 0, print_resolved = 0;

	/*
	 * In order to allow a failed clone to be resumed with 'got fetch'
	 * we try to create configuration files as soon as possible.
	 * Once the server has sent information about its default branch
	 * we have all required information.
	 */
	if (a->create_configs && !a->configs_created &&
	    !TAILQ_EMPTY(a->config_info.symrefs)) {
		err = create_config_files(a->config_info.proto,
		    a->config_info.host, a->config_info.port,
		    a->config_info.remote_repo_path,
		    a->config_info.git_url,
		    a->config_info.fetch_all_branches,
		    a->config_info.mirror_references,
		    a->config_info.symrefs,
		    a->config_info.wanted_branches, a->repo);
		if (err)
			return err;
		a->configs_created = 1;
	}

	if (a->verbosity < 0)
		return NULL;

	if (message && message[0] != '\0') {
		printf("\rserver: %s", message);
		fflush(stdout);
		return NULL;
	}

	if (packfile_size > 0 || nobj_indexed > 0) {
		if (fmt_scaled(packfile_size, scaled_size) == 0 &&
		    (a->last_scaled_size[0] == '\0' ||
		    strcmp(scaled_size, a->last_scaled_size)) != 0) {
			print_size = 1;
			if (strlcpy(a->last_scaled_size, scaled_size,
			    FMT_SCALED_STRSIZE) >= FMT_SCALED_STRSIZE)
				return got_error(GOT_ERR_NO_SPACE);
		}
		if (nobj_indexed > 0) {
			p_indexed = (nobj_indexed * 100) / nobj_total;
			if (p_indexed != a->last_p_indexed) {
				a->last_p_indexed = p_indexed;
				print_indexed = 1;
				print_size = 1;
			}
		}
		if (nobj_resolved > 0) {
			p_resolved = (nobj_resolved * 100) /
			    (nobj_total - nobj_loose);
			if (p_resolved != a->last_p_resolved) {
				a->last_p_resolved = p_resolved;
				print_resolved = 1;
				print_indexed = 1;
				print_size = 1;
			}
		}

	}
	if (print_size || print_indexed || print_resolved)
		printf("\r");
	if (print_size)
		printf("%*s fetched", FMT_SCALED_STRSIZE, scaled_size);
	if (print_indexed)
		printf("; indexing %d%%", p_indexed);
	if (print_resolved)
		printf("; resolving deltas %d%%", p_resolved);
	if (print_size || print_indexed || print_resolved)
		fflush(stdout);

	return NULL;
}

static const struct got_error *
create_symref(const char *refname, struct got_reference *target_ref,
    int verbosity, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_reference *head_symref;

	err = got_ref_alloc_symref(&head_symref, refname, target_ref);
	if (err)
		return err;

	err = got_ref_write(head_symref, repo);
	if (err == NULL && verbosity > 0) {
		printf("Created reference %s: %s\n", GOT_REF_HEAD,
		    got_ref_get_name(target_ref));
	}
	got_ref_close(head_symref);
	return err;
}

static const struct got_error *
list_remote_refs(struct got_pathlist_head *symrefs,
    struct got_pathlist_head *refs)
{
	const struct got_error *err;
	struct got_pathlist_entry *pe;

	TAILQ_FOREACH(pe, symrefs, entry) {
		const char *refname = pe->path;
		const char *targetref = pe->data;

		printf("%s: %s\n", refname, targetref);
	}

	TAILQ_FOREACH(pe, refs, entry) {
		const char *refname = pe->path;
		struct got_object_id *id = pe->data;
		char *id_str;

		err = got_object_id_str(&id_str, id);
		if (err)
			return err;
		printf("%s: %s\n", refname, id_str);
		free(id_str);
	}

	return NULL;
}

static const struct got_error *
create_ref(const char *refname, struct got_object_id *id,
    int verbosity, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_reference *ref;
	char *id_str;

	err = got_object_id_str(&id_str, id);
	if (err)
		return err;

	err = got_ref_alloc(&ref, refname, id);
	if (err)
		goto done;

	err = got_ref_write(ref, repo);
	got_ref_close(ref);

	if (err == NULL && verbosity >= 0)
		printf("Created reference %s: %s\n", refname, id_str);
done:
	free(id_str);
	return err;
}

static int
match_wanted_ref(const char *refname, const char *wanted_ref)
{
	if (strncmp(refname, "refs/", 5) != 0)
		return 0;
	refname += 5;

	/*
	 * Prevent fetching of references that won't make any
	 * sense outside of the remote repository's context.
	 */
	if (strncmp(refname, "got/", 4) == 0)
		return 0;
	if (strncmp(refname, "remotes/", 8) == 0)
		return 0;

	if (strncmp(wanted_ref, "refs/", 5) == 0)
		wanted_ref += 5;

	/* Allow prefix match. */
	if (got_path_is_child(refname, wanted_ref, strlen(wanted_ref)))
		return 1;

	/* Allow exact match. */
	return (strcmp(refname, wanted_ref) == 0);
}

static int
is_wanted_ref(struct got_pathlist_head *wanted_refs, const char *refname)
{
	struct got_pathlist_entry *pe;

	TAILQ_FOREACH(pe, wanted_refs, entry) {
		if (match_wanted_ref(refname, pe->path))
			return 1;
	}

	return 0;
}

static const struct got_error *
create_wanted_ref(const char *refname, struct got_object_id *id,
    const char *remote_repo_name, int verbosity, struct got_repository *repo)
{
	const struct got_error *err;
	char *remote_refname;

	if (strncmp("refs/", refname, 5) == 0)
		refname += 5;

	if (asprintf(&remote_refname, "refs/remotes/%s/%s",
	    remote_repo_name, refname) == -1)
		return got_error_from_errno("asprintf");

	err = create_ref(remote_refname, id, verbosity, repo);
	free(remote_refname);
	return err;
}

static const struct got_error *
create_gotconfig(const char *proto, const char *host, const char *port,
    const char *remote_repo_path, int fetch_all_branches, int mirror_references,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *gotconfig_path = NULL;
	char *gotconfig = NULL;
	FILE *gotconfig_file = NULL;
	ssize_t n;

	/* Create got.conf(5). */
	gotconfig_path = got_repo_get_path_gotconfig(repo);
	if (gotconfig_path == NULL) {
		err = got_error_from_errno("got_repo_get_path_gotconfig");
		goto done;
	}
	gotconfig_file = fopen(gotconfig_path, "a");
	if (gotconfig_file == NULL) {
		err = got_error_from_errno2("fopen", gotconfig_path);
		goto done;
	}
	if (asprintf(&gotconfig,
	    "remote \"%s\" {\n"
	    "\tserver %s\n"
	    "\tprotocol %s\n"
	    "%s%s%s"
	    "\trepository \"%s\"\n"
	    "%s"
	    "}\n",
	    GOT_FETCH_DEFAULT_REMOTE_NAME, host, proto,
	    port ? "\tport " : "", port ? port : "", port ? "\n" : "",
	    remote_repo_path,
	    mirror_references ? "\tmirror-references yes\n" : "") == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	n = fwrite(gotconfig, 1, strlen(gotconfig), gotconfig_file);
	if (n != strlen(gotconfig)) {
		err = got_ferror(gotconfig_file, GOT_ERR_IO);
		goto done;
	}

done:
	if (gotconfig_file && fclose(gotconfig_file) == EOF && err == NULL)
		err = got_error_from_errno2("fclose", gotconfig_path);
	free(gotconfig_path);
	return err;
}

static const struct got_error *
create_gitconfig(const char *git_url, const char *default_branch,
    int fetch_all_branches, int mirror_references, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *gitconfig_path = NULL;
	char *gitconfig = NULL;
	FILE *gitconfig_file = NULL;
	ssize_t n;

	/* Create a config file Git can understand. */
	gitconfig_path = got_repo_get_path_gitconfig(repo);
	if (gitconfig_path == NULL) {
		err = got_error_from_errno("got_repo_get_path_gitconfig");
		goto done;
	}
	gitconfig_file = fopen(gitconfig_path, "a");
	if (gitconfig_file == NULL) {
		err = got_error_from_errno2("fopen", gitconfig_path);
		goto done;
	}
	if (mirror_references) {
		if (asprintf(&gitconfig,
		    "[remote \"%s\"]\n"
		    "\turl = %s\n"
		    "\tfetch = +refs/*:refs/*\n"
		    "\tmirror = true\n",
		    GOT_FETCH_DEFAULT_REMOTE_NAME, git_url) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
	} else if (fetch_all_branches) {
		if (asprintf(&gitconfig,
		    "[remote \"%s\"]\n"
		    "\turl = %s\n"
		    "\tfetch = +refs/heads/*:refs/remotes/%s/*\n",
		    GOT_FETCH_DEFAULT_REMOTE_NAME, git_url,
		    GOT_FETCH_DEFAULT_REMOTE_NAME) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
	} else {
		const char *branchname;

		/*
		 * If the server specified a default branch, use just that one.
		 * Otherwise fall back to fetching all branches on next fetch.
		 */
		if (default_branch) {
			branchname = default_branch;
			if (strncmp(branchname, "refs/heads/", 11) == 0)
				branchname += 11;
		} else
			branchname = "*"; /* fall back to all branches */
		if (asprintf(&gitconfig,
		    "[remote \"%s\"]\n"
		    "\turl = %s\n"
		    "\tfetch = +refs/heads/%s:refs/remotes/%s/%s\n",
		    GOT_FETCH_DEFAULT_REMOTE_NAME, git_url,
		    branchname, GOT_FETCH_DEFAULT_REMOTE_NAME,
		    branchname) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
	}
	n = fwrite(gitconfig, 1, strlen(gitconfig), gitconfig_file);
	if (n != strlen(gitconfig)) {
		err = got_ferror(gitconfig_file, GOT_ERR_IO);
		goto done;
	}
done:
	if (gitconfig_file && fclose(gitconfig_file) == EOF && err == NULL)
		err = got_error_from_errno2("fclose", gitconfig_path);
	free(gitconfig_path);
	return err;
}

static const struct got_error *
create_config_files(const char *proto, const char *host, const char *port,
    const char *remote_repo_path, const char *git_url, int fetch_all_branches,
    int mirror_references, struct got_pathlist_head *symrefs,
    struct got_pathlist_head *wanted_branches, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	const char *default_branch = NULL;
	struct got_pathlist_entry *pe;

	/*
	 * If we asked for a set of wanted branches then use the first
	 * one of those.
	 */
	if (!TAILQ_EMPTY(wanted_branches)) {
		pe = TAILQ_FIRST(wanted_branches);
		default_branch = pe->path;
	} else {
		/* First HEAD ref listed by server is the default branch. */
		TAILQ_FOREACH(pe, symrefs, entry) {
			const char *refname = pe->path;
			const char *target = pe->data;

			if (strcmp(refname, GOT_REF_HEAD) != 0)
				continue;

			default_branch = target;
			break;
		}
	}

	/* Create got.conf(5). */
	err = create_gotconfig(proto, host, port, remote_repo_path,
	    fetch_all_branches, mirror_references, repo);
	if (err)
		return err;

	/* Create a config file Git can understand. */
	return create_gitconfig(git_url, default_branch, fetch_all_branches,
	    mirror_references, repo);
}

static const struct got_error *
cmd_clone(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	const char *uri, *dirname;
	char *proto, *host, *port, *repo_name, *server_path;
	char *default_destdir = NULL, *id_str = NULL;
	const char *repo_path;
	struct got_repository *repo = NULL;
	struct got_pathlist_head refs, symrefs, wanted_branches, wanted_refs;
	struct got_pathlist_entry *pe;
	struct got_object_id *pack_hash = NULL;
	int ch, fetchfd = -1, fetchstatus;
	pid_t fetchpid = -1;
	struct got_fetch_progress_arg fpa;
	char *git_url = NULL;
	int verbosity = 0, fetch_all_branches = 0, mirror_references = 0;
	int list_refs_only = 0;

	TAILQ_INIT(&refs);
	TAILQ_INIT(&symrefs);
	TAILQ_INIT(&wanted_branches);
	TAILQ_INIT(&wanted_refs);

	while ((ch = getopt(argc, argv, "ab:lmvqR:")) != -1) {
		switch (ch) {
		case 'a':
			fetch_all_branches = 1;
			break;
		case 'b':
			error = got_pathlist_append(&wanted_branches,
			    optarg, NULL);
			if (error)
				return error;
			break;
		case 'l':
			list_refs_only = 1;
			break;
		case 'm':
			mirror_references = 1;
			break;
		case 'v':
			if (verbosity < 0)
				verbosity = 0;
			else if (verbosity < 3)
				verbosity++;
			break;
		case 'q':
			verbosity = -1;
			break;
		case 'R':
			error = got_pathlist_append(&wanted_refs,
			    optarg, NULL);
			if (error)
				return error;
			break;
		default:
			usage_clone();
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (fetch_all_branches && !TAILQ_EMPTY(&wanted_branches))
		option_conflict('a', 'b');
	if (list_refs_only) {
		if (!TAILQ_EMPTY(&wanted_branches))
			option_conflict('l', 'b');
		if (fetch_all_branches)
			option_conflict('l', 'a');
		if (mirror_references)
			option_conflict('l', 'm');
		if (verbosity == -1)
			option_conflict('l', 'q');
		if (!TAILQ_EMPTY(&wanted_refs))
			option_conflict('l', 'R');
	}

	uri = argv[0];

	if (argc == 1)
		dirname = NULL;
	else if (argc == 2)
		dirname = argv[1];
	else
		usage_clone();

	error = got_fetch_parse_uri(&proto, &host, &port, &server_path,
	    &repo_name, uri);
	if (error)
		goto done;

	if (asprintf(&git_url, "%s://%s%s%s%s%s", proto,
	    host, port ? ":" : "", port ? port : "",
	    server_path[0] != '/' ? "/" : "", server_path) == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}

	if (strcmp(proto, "git") == 0) {
#ifndef PROFILE
		if (pledge("stdio rpath wpath cpath fattr flock proc exec "
		    "sendfd dns inet unveil", NULL) == -1)
			err(1, "pledge");
#endif
	} else if (strcmp(proto, "git+ssh") == 0 ||
	    strcmp(proto, "ssh") == 0) {
#ifndef PROFILE
		if (pledge("stdio rpath wpath cpath fattr flock proc exec "
		    "sendfd unveil", NULL) == -1)
			err(1, "pledge");
#endif
	} else if (strcmp(proto, "http") == 0 ||
	    strcmp(proto, "git+http") == 0) {
		error = got_error_path(proto, GOT_ERR_NOT_IMPL);
		goto done;
	} else {
		error = got_error_path(proto, GOT_ERR_BAD_PROTO);
		goto done;
	}
	if (dirname == NULL) {
		if (asprintf(&default_destdir, "%s.git", repo_name) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}
		repo_path = default_destdir;
	} else
		repo_path = dirname;

	if (!list_refs_only) {
		error = got_path_mkdir(repo_path);
		if (error &&
		    (!(error->code == GOT_ERR_ERRNO && errno == EISDIR) &&
		    !(error->code == GOT_ERR_ERRNO && errno == EEXIST)))
			goto done;
		if (!got_path_dir_is_empty(repo_path)) {
			error = got_error_path(repo_path,
			    GOT_ERR_DIR_NOT_EMPTY);
			goto done;
		}
	}

	if (strcmp(proto, "git+ssh") == 0 || strcmp(proto, "ssh") == 0) {
		if (unveil(GOT_FETCH_PATH_SSH, "x") != 0) {
			error = got_error_from_errno2("unveil",
			    GOT_FETCH_PATH_SSH);
			goto done;
		}
	}
	error = apply_unveil(repo_path, 0, NULL);
	if (error)
		goto done;

	if (verbosity >= 0)
		printf("Connecting to %s%s%s\n", host,
		    port ? ":" : "", port ? port : "");

	error = got_fetch_connect(&fetchpid, &fetchfd, proto, host, port,
	    server_path, verbosity);
	if (error)
		goto done;

	if (!list_refs_only) {
		error = got_repo_init(repo_path);
		if (error)
			goto done;
		error = got_repo_open(&repo, repo_path, NULL);
		if (error)
			goto done;
	}

	fpa.last_scaled_size[0] = '\0';
	fpa.last_p_indexed = -1;
	fpa.last_p_resolved = -1;
	fpa.verbosity = verbosity;
	fpa.create_configs = 1;
	fpa.configs_created = 0;
	fpa.repo = repo;
	fpa.config_info.symrefs = &symrefs;
	fpa.config_info.wanted_branches = &wanted_branches;
	fpa.config_info.proto = proto;
	fpa.config_info.host = host;
	fpa.config_info.port = port;
	fpa.config_info.remote_repo_path = server_path;
	fpa.config_info.git_url = git_url;
	fpa.config_info.fetch_all_branches = fetch_all_branches;
	fpa.config_info.mirror_references = mirror_references;
	error = got_fetch_pack(&pack_hash, &refs, &symrefs,
	    GOT_FETCH_DEFAULT_REMOTE_NAME, mirror_references,
	    fetch_all_branches, &wanted_branches, &wanted_refs,
	    list_refs_only, verbosity, fetchfd, repo,
	    fetch_progress, &fpa);
	if (error)
		goto done;

	if (list_refs_only) {
		error = list_remote_refs(&symrefs, &refs);
		goto done;
	}

	error = got_object_id_str(&id_str, pack_hash);
	if (error)
		goto done;
	if (verbosity >= 0)
		printf("\nFetched %s.pack\n", id_str);
	free(id_str);

	/* Set up references provided with the pack file. */
	TAILQ_FOREACH(pe, &refs, entry) {
		const char *refname = pe->path;
		struct got_object_id *id = pe->data;
		char *remote_refname;

		if (is_wanted_ref(&wanted_refs, refname) &&
		    !mirror_references) {
			error = create_wanted_ref(refname, id,
			    GOT_FETCH_DEFAULT_REMOTE_NAME,
			    verbosity - 1, repo);
			if (error)
				goto done;
			continue;
		}

		error = create_ref(refname, id, verbosity - 1, repo);
		if (error)
			goto done;

		if (mirror_references)
			continue;

		if (strncmp("refs/heads/", refname, 11) != 0)
			continue;

		if (asprintf(&remote_refname,
		    "refs/remotes/%s/%s", GOT_FETCH_DEFAULT_REMOTE_NAME,
		    refname + 11) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}
		error = create_ref(remote_refname, id, verbosity - 1, repo);
		free(remote_refname);
		if (error)
			goto done;
	}

	/* Set the HEAD reference if the server provided one. */
	TAILQ_FOREACH(pe, &symrefs, entry) {
		struct got_reference *target_ref;
		const char *refname = pe->path;
		const char *target = pe->data;
		char *remote_refname = NULL, *remote_target = NULL;

		if (strcmp(refname, GOT_REF_HEAD) != 0)
			continue;

		error = got_ref_open(&target_ref, repo, target, 0);
		if (error) {
			if (error->code == GOT_ERR_NOT_REF) {
				error = NULL;
				continue;
			}
			goto done;
		}

		error = create_symref(refname, target_ref, verbosity, repo);
		got_ref_close(target_ref);
		if (error)
			goto done;

		if (mirror_references)
			continue;

		if (strncmp("refs/heads/", target, 11) != 0)
			continue;

		if (asprintf(&remote_refname,
		    "refs/remotes/%s/%s", GOT_FETCH_DEFAULT_REMOTE_NAME,
		    refname) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}
		if (asprintf(&remote_target,
		    "refs/remotes/%s/%s", GOT_FETCH_DEFAULT_REMOTE_NAME,
		    target + 11) == -1) {
			error = got_error_from_errno("asprintf");
			free(remote_refname);
			goto done;
		}
		error = got_ref_open(&target_ref, repo, remote_target, 0);
		if (error) {
			free(remote_refname);
			free(remote_target);
			if (error->code == GOT_ERR_NOT_REF) {
				error = NULL;
				continue;
			}
			goto done;
		}
		error = create_symref(remote_refname, target_ref,
		    verbosity - 1, repo);
		free(remote_refname);
		free(remote_target);
		got_ref_close(target_ref);
		if (error)
			goto done;
	}
	if (pe == NULL) {
		/*
		 * We failed to set the HEAD reference. If we asked for
		 * a set of wanted branches use the first of one of those
		 * which could be fetched instead.
		 */
		TAILQ_FOREACH(pe, &wanted_branches, entry) {
			const char *target = pe->path;
			struct got_reference *target_ref;

			error = got_ref_open(&target_ref, repo, target, 0);
			if (error) {
				if (error->code == GOT_ERR_NOT_REF) {
					error = NULL;
					continue;
				}
				goto done;
			}

			error = create_symref(GOT_REF_HEAD, target_ref,
			    verbosity, repo);
			got_ref_close(target_ref);
			if (error)
				goto done;
			break;
		}
	}

	if (verbosity >= 0)
		printf("Created %s repository '%s'\n",
		    mirror_references ? "mirrored" : "cloned", repo_path);
done:
	if (fetchpid > 0) {
		if (kill(fetchpid, SIGTERM) == -1)
			error = got_error_from_errno("kill");
		if (waitpid(fetchpid, &fetchstatus, 0) == -1 && error == NULL)
			error = got_error_from_errno("waitpid");
	}
	if (fetchfd != -1 && close(fetchfd) == -1 && error == NULL)
		error = got_error_from_errno("close");
	if (repo)
		got_repo_close(repo);
	TAILQ_FOREACH(pe, &refs, entry) {
		free((void *)pe->path);
		free(pe->data);
	}
	got_pathlist_free(&refs);
	TAILQ_FOREACH(pe, &symrefs, entry) {
		free((void *)pe->path);
		free(pe->data);
	}
	got_pathlist_free(&symrefs);
	got_pathlist_free(&wanted_branches);
	got_pathlist_free(&wanted_refs);
	free(pack_hash);
	free(proto);
	free(host);
	free(port);
	free(server_path);
	free(repo_name);
	free(default_destdir);
	free(git_url);
	return error;
}

static const struct got_error *
update_ref(struct got_reference *ref, struct got_object_id *new_id,
    int replace_tags, int verbosity, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *new_id_str = NULL;
	struct got_object_id *old_id = NULL;

	err = got_object_id_str(&new_id_str, new_id);
	if (err)
		goto done;

	if (!replace_tags &&
	    strncmp(got_ref_get_name(ref), "refs/tags/", 10) == 0) {
		err = got_ref_resolve(&old_id, repo, ref);
		if (err)
			goto done;
		if (got_object_id_cmp(old_id, new_id) == 0)
			goto done;
		if (verbosity >= 0) {
			printf("Rejecting update of existing tag %s: %s\n",
			    got_ref_get_name(ref), new_id_str);
		}
		goto done;
	}

	if (got_ref_is_symbolic(ref)) {
		if (verbosity >= 0) {
			printf("Replacing reference %s: %s\n",
			    got_ref_get_name(ref),
			    got_ref_get_symref_target(ref));
		}
		err = got_ref_change_symref_to_ref(ref, new_id);
		if (err)
			goto done;
		err = got_ref_write(ref, repo);
		if (err)
			goto done;
	} else {
		err = got_ref_resolve(&old_id, repo, ref);
		if (err)
			goto done;
		if (got_object_id_cmp(old_id, new_id) == 0)
			goto done;

		err = got_ref_change_ref(ref, new_id);
		if (err)
			goto done;
		err = got_ref_write(ref, repo);
		if (err)
			goto done;
	}

	if (verbosity >= 0)
		printf("Updated %s: %s\n", got_ref_get_name(ref),
		    new_id_str);
done:
	free(old_id);
	free(new_id_str);
	return err;
}

static const struct got_error *
update_symref(const char *refname, struct got_reference *target_ref,
    int verbosity, struct got_repository *repo)
{
	const struct got_error *err = NULL, *unlock_err;
	struct got_reference *symref;
	int symref_is_locked = 0;

	err = got_ref_open(&symref, repo, refname, 1);
	if (err) {
		if (err->code != GOT_ERR_NOT_REF)
			return err;
		err = got_ref_alloc_symref(&symref, refname, target_ref);
		if (err)
			goto done;

		err = got_ref_write(symref, repo);
		if (err)
			goto done;

		if (verbosity >= 0)
			printf("Created reference %s: %s\n",
			    got_ref_get_name(symref),
			    got_ref_get_symref_target(symref));
	} else {
		symref_is_locked = 1;

		if (strcmp(got_ref_get_symref_target(symref),
		    got_ref_get_name(target_ref)) == 0)
			goto done;

		err = got_ref_change_symref(symref,
		    got_ref_get_name(target_ref));
		if (err)
			goto done;

		err = got_ref_write(symref, repo);
		if (err)
			goto done;

		if (verbosity >= 0)
			printf("Updated %s: %s\n", got_ref_get_name(symref),
			    got_ref_get_symref_target(symref));

	}
done:
	if (symref_is_locked) {
		unlock_err = got_ref_unlock(symref);
		if (unlock_err && err == NULL)
			err = unlock_err;
	}
	got_ref_close(symref);
	return err;
}

__dead static void
usage_fetch(void)
{
	fprintf(stderr, "usage: %s fetch [-a] [-b branch] [-d] [-l] "
	    "[-r repository-path] [-t] [-q] [-v] [-R reference] "
	    "[remote-repository-name]\n",
	    getprogname());
	exit(1);
}

static const struct got_error *
delete_missing_ref(struct got_reference *ref,
    int verbosity, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object_id *id = NULL;
	char *id_str = NULL;

	if (got_ref_is_symbolic(ref)) {
		err = got_ref_delete(ref, repo);
		if (err)
			return err;
		if (verbosity >= 0) {
			printf("Deleted reference %s: %s\n",
			    got_ref_get_name(ref),
			    got_ref_get_symref_target(ref));
		}
	} else {
		err = got_ref_resolve(&id, repo, ref);
		if (err)
			return err;
		err = got_object_id_str(&id_str, id);
		if (err)
			goto done;

		err = got_ref_delete(ref, repo);
		if (err)
			goto done;
		if (verbosity >= 0) {
			printf("Deleted reference %s: %s\n",
			    got_ref_get_name(ref), id_str);
		}
	}
done:
	free(id);
	free(id_str);
	return NULL;
}

static const struct got_error *
delete_missing_refs(struct got_pathlist_head *their_refs,
    struct got_pathlist_head *their_symrefs,
    const struct got_remote_repo *remote,
    int verbosity, struct got_repository *repo)
{
	const struct got_error *err = NULL, *unlock_err;
	struct got_reflist_head my_refs;
	struct got_reflist_entry *re;
	struct got_pathlist_entry *pe;
	char *remote_namespace = NULL;
	char *local_refname = NULL;

	SIMPLEQ_INIT(&my_refs);

	if (asprintf(&remote_namespace, "refs/remotes/%s/", remote->name)
	    == -1)
		return got_error_from_errno("asprintf");

	err = got_ref_list(&my_refs, repo, NULL, got_ref_cmp_by_name, NULL);
	if (err)
		goto done;

	SIMPLEQ_FOREACH(re, &my_refs, entry) {
		const char *refname = got_ref_get_name(re->ref);

		if (!remote->mirror_references) {
			if (strncmp(refname, remote_namespace,
			    strlen(remote_namespace)) == 0) {
				if (strcmp(refname + strlen(remote_namespace),
				    GOT_REF_HEAD) == 0)
					continue;
				if (asprintf(&local_refname, "refs/heads/%s",
				    refname + strlen(remote_namespace)) == -1) {
					err = got_error_from_errno("asprintf");
					goto done;
				}
			} else if (strncmp(refname, "refs/tags/", 10) != 0)
				continue;
		}

		TAILQ_FOREACH(pe, their_refs, entry) {
			if (strcmp(local_refname, pe->path) == 0)
				break;
		}
		if (pe != NULL)
			continue;

		TAILQ_FOREACH(pe, their_symrefs, entry) {
			if (strcmp(local_refname, pe->path) == 0)
				break;
		}
		if (pe != NULL)
			continue;

		err = delete_missing_ref(re->ref, verbosity, repo);
		if (err)
			break;

		if (local_refname) {
			struct got_reference *ref;
			err = got_ref_open(&ref, repo, local_refname, 1);
			if (err) {
				if (err->code != GOT_ERR_NOT_REF)
					break;
				free(local_refname);
				local_refname = NULL;
				continue;
			}
			err = delete_missing_ref(ref, verbosity, repo);
			if (err)
				break;
			unlock_err = got_ref_unlock(ref);
			got_ref_close(ref);
			if (unlock_err && err == NULL) {
				err = unlock_err;
				break;
			}

			free(local_refname);
			local_refname = NULL;
		}
	}
done:
	free(remote_namespace);
	free(local_refname);
	return err;
}

static const struct got_error *
update_wanted_ref(const char *refname, struct got_object_id *id,
    const char *remote_repo_name, int verbosity, struct got_repository *repo)
{
	const struct got_error *err, *unlock_err;
	char *remote_refname;
	struct got_reference *ref;

	if (strncmp("refs/", refname, 5) == 0)
		refname += 5;

	if (asprintf(&remote_refname, "refs/remotes/%s/%s",
	    remote_repo_name, refname) == -1)
		return got_error_from_errno("asprintf");

	err = got_ref_open(&ref, repo, remote_refname, 1);
	if (err) {
		if (err->code != GOT_ERR_NOT_REF)
			goto done;
		err = create_ref(remote_refname, id, verbosity, repo);
	} else {
		err = update_ref(ref, id, 0, verbosity, repo);
		unlock_err = got_ref_unlock(ref);
		if (unlock_err && err == NULL)
			err = unlock_err;
		got_ref_close(ref);
	}
done:
	free(remote_refname);
	return err;
}

static const struct got_error *
cmd_fetch(int argc, char *argv[])
{
	const struct got_error *error = NULL, *unlock_err;
	char *cwd = NULL, *repo_path = NULL;
	const char *remote_name;
	char *proto = NULL, *host = NULL, *port = NULL;
	char *repo_name = NULL, *server_path = NULL;
	const struct got_remote_repo *remotes, *remote = NULL;
	int nremotes;
	char *id_str = NULL;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	const struct got_gotconfig *repo_conf = NULL, *worktree_conf = NULL;
	struct got_pathlist_head refs, symrefs, wanted_branches, wanted_refs;
	struct got_pathlist_entry *pe;
	struct got_object_id *pack_hash = NULL;
	int i, ch, fetchfd = -1, fetchstatus;
	pid_t fetchpid = -1;
	struct got_fetch_progress_arg fpa;
	int verbosity = 0, fetch_all_branches = 0, list_refs_only = 0;
	int delete_refs = 0, replace_tags = 0;

	TAILQ_INIT(&refs);
	TAILQ_INIT(&symrefs);
	TAILQ_INIT(&wanted_branches);
	TAILQ_INIT(&wanted_refs);

	while ((ch = getopt(argc, argv, "ab:dlr:tvqR:")) != -1) {
		switch (ch) {
		case 'a':
			fetch_all_branches = 1;
			break;
		case 'b':
			error = got_pathlist_append(&wanted_branches,
			    optarg, NULL);
			if (error)
				return error;
			break;
		case 'd':
			delete_refs = 1;
			break;
		case 'l':
			list_refs_only = 1;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				return got_error_from_errno2("realpath",
				    optarg);
			got_path_strip_trailing_slashes(repo_path);
			break;
		case 't':
			replace_tags = 1;
			break;
		case 'v':
			if (verbosity < 0)
				verbosity = 0;
			else if (verbosity < 3)
				verbosity++;
			break;
		case 'q':
			verbosity = -1;
			break;
		case 'R':
			error = got_pathlist_append(&wanted_refs,
			    optarg, NULL);
			if (error)
				return error;
			break;
		default:
			usage_fetch();
			break;
		}
	}
	argc -= optind;
	argv += optind;

	if (fetch_all_branches && !TAILQ_EMPTY(&wanted_branches))
		option_conflict('a', 'b');
	if (list_refs_only) {
		if (!TAILQ_EMPTY(&wanted_branches))
			option_conflict('l', 'b');
		if (fetch_all_branches)
			option_conflict('l', 'a');
		if (delete_refs)
			option_conflict('l', 'd');
		if (verbosity == -1)
			option_conflict('l', 'q');
	}

	if (argc == 0)
		remote_name = GOT_FETCH_DEFAULT_REMOTE_NAME;
	else if (argc == 1)
		remote_name = argv[0];
	else
		usage_fetch();

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

	error = got_repo_open(&repo, repo_path, NULL);
	if (error)
		goto done;

	if (worktree) {
		worktree_conf = got_worktree_get_gotconfig(worktree);
		if (worktree_conf) {
			got_gotconfig_get_remotes(&nremotes, &remotes,
			    worktree_conf);
			for (i = 0; i < nremotes; i++) {
				if (strcmp(remotes[i].name, remote_name) == 0) {
					remote = &remotes[i];
					break;
				}
			}
		}
	}
	if (remote == NULL) {
		repo_conf = got_repo_get_gotconfig(repo);
		if (repo_conf) {
			got_gotconfig_get_remotes(&nremotes, &remotes,
			    repo_conf);
			for (i = 0; i < nremotes; i++) {
				if (strcmp(remotes[i].name, remote_name) == 0) {
					remote = &remotes[i];
					break;
				}
			}
		}
	}
	if (remote == NULL) {
		got_repo_get_gitconfig_remotes(&nremotes, &remotes, repo);
		for (i = 0; i < nremotes; i++) {
			if (strcmp(remotes[i].name, remote_name) == 0) {
				remote = &remotes[i];
				break;
			}
		}
	}
	if (remote == NULL) {
		error = got_error_path(remote_name, GOT_ERR_NO_REMOTE);
		goto done;
	}

	if (TAILQ_EMPTY(&wanted_branches) && remote->nbranches > 0) {
		for (i = 0; i < remote->nbranches; i++) {
			got_pathlist_append(&wanted_branches,
			    remote->branches[i], NULL);
		}

	}

	error = got_fetch_parse_uri(&proto, &host, &port, &server_path,
	    &repo_name, remote->url);
	if (error)
		goto done;

	if (strcmp(proto, "git") == 0) {
#ifndef PROFILE
		if (pledge("stdio rpath wpath cpath fattr flock proc exec "
		    "sendfd dns inet unveil", NULL) == -1)
			err(1, "pledge");
#endif
	} else if (strcmp(proto, "git+ssh") == 0 ||
	    strcmp(proto, "ssh") == 0) {
#ifndef PROFILE
		if (pledge("stdio rpath wpath cpath fattr flock proc exec "
		    "sendfd unveil", NULL) == -1)
			err(1, "pledge");
#endif
	} else if (strcmp(proto, "http") == 0 ||
	    strcmp(proto, "git+http") == 0) {
		error = got_error_path(proto, GOT_ERR_NOT_IMPL);
		goto done;
	} else {
		error = got_error_path(proto, GOT_ERR_BAD_PROTO);
		goto done;
	}

	if (strcmp(proto, "git+ssh") == 0 || strcmp(proto, "ssh") == 0) {
		if (unveil(GOT_FETCH_PATH_SSH, "x") != 0) {
			error = got_error_from_errno2("unveil",
			    GOT_FETCH_PATH_SSH);
			goto done;
		}
	}
	error = apply_unveil(got_repo_get_path(repo), 0, NULL);
	if (error)
		goto done;

	if (verbosity >= 0)
		printf("Connecting to \"%s\" %s%s%s\n", remote->name, host,
		    port ? ":" : "", port ? port : "");

	error = got_fetch_connect(&fetchpid, &fetchfd, proto, host, port,
	    server_path, verbosity);
	if (error)
		goto done;

	fpa.last_scaled_size[0] = '\0';
	fpa.last_p_indexed = -1;
	fpa.last_p_resolved = -1;
	fpa.verbosity = verbosity;
	fpa.repo = repo;
	fpa.create_configs = 0;
	fpa.configs_created = 0;
	memset(&fpa.config_info, 0, sizeof(fpa.config_info));
	error = got_fetch_pack(&pack_hash, &refs, &symrefs, remote->name,
	    remote->mirror_references, fetch_all_branches, &wanted_branches,
	    &wanted_refs, list_refs_only, verbosity, fetchfd, repo,
	    fetch_progress, &fpa);
	if (error)
		goto done;

	if (list_refs_only) {
		error = list_remote_refs(&symrefs, &refs);
		goto done;
	}

	if (pack_hash == NULL) {
		if (verbosity >= 0)
			printf("Already up-to-date\n");
	} else if (verbosity >= 0) {
		error = got_object_id_str(&id_str, pack_hash);
		if (error)
			goto done;
		printf("\nFetched %s.pack\n", id_str);
		free(id_str);
		id_str = NULL;
	}

	/* Update references provided with the pack file. */
	TAILQ_FOREACH(pe, &refs, entry) {
		const char *refname = pe->path;
		struct got_object_id *id = pe->data;
		struct got_reference *ref;
		char *remote_refname;

		if (is_wanted_ref(&wanted_refs, refname) &&
		    !remote->mirror_references) {
			error = update_wanted_ref(refname, id,
			    remote->name, verbosity, repo);
			if (error)
				goto done;
			continue;
		}

		if (remote->mirror_references ||
		    strncmp("refs/tags/", refname, 10) == 0) {
			error = got_ref_open(&ref, repo, refname, 1);
			if (error) {
				if (error->code != GOT_ERR_NOT_REF)
					goto done;
				error = create_ref(refname, id, verbosity,
				    repo);
				if (error)
					goto done;
			} else {
				error = update_ref(ref, id, replace_tags,
				    verbosity, repo);
				unlock_err = got_ref_unlock(ref);
				if (unlock_err && error == NULL)
					error = unlock_err;
				got_ref_close(ref);
				if (error)
					goto done;
			}
		} else if (strncmp("refs/heads/", refname, 11) == 0) {
			if (asprintf(&remote_refname, "refs/remotes/%s/%s",
			    remote_name, refname + 11) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}

			error = got_ref_open(&ref, repo, remote_refname, 1);
			if (error) {
				if (error->code != GOT_ERR_NOT_REF)
					goto done;
				error = create_ref(remote_refname, id, 
				    verbosity, repo);
				if (error)
					goto done;
			} else {
				error = update_ref(ref, id, replace_tags,
				    verbosity, repo);
				unlock_err = got_ref_unlock(ref);
				if (unlock_err && error == NULL)
					error = unlock_err;
				got_ref_close(ref);
				if (error)
					goto done;
			}

			/* Also create a local branch if none exists yet. */
			error = got_ref_open(&ref, repo, refname, 1);
			if (error) {
				if (error->code != GOT_ERR_NOT_REF)
					goto done;
				error = create_ref(refname, id, verbosity,
				    repo);
				if (error)
					goto done;
			} else {
				unlock_err = got_ref_unlock(ref);
				if (unlock_err && error == NULL)
					error = unlock_err;
				got_ref_close(ref);
			}
		}
	}
	if (delete_refs) {
		error = delete_missing_refs(&refs, &symrefs, remote,
		    verbosity, repo);
		if (error)
			goto done;
	}

	if (!remote->mirror_references) {
		/* Update remote HEAD reference if the server provided one. */
		TAILQ_FOREACH(pe, &symrefs, entry) {
			struct got_reference *target_ref;
			const char *refname = pe->path;
			const char *target = pe->data;
			char *remote_refname = NULL, *remote_target = NULL;

			if (strcmp(refname, GOT_REF_HEAD) != 0)
				continue;

			if (strncmp("refs/heads/", target, 11) != 0)
				continue;

			if (asprintf(&remote_refname, "refs/remotes/%s/%s",
			    remote->name, refname) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}
			if (asprintf(&remote_target, "refs/remotes/%s/%s",
			    remote->name, target + 11) == -1) {
				error = got_error_from_errno("asprintf");
				free(remote_refname);
				goto done;
			}

			error = got_ref_open(&target_ref, repo, remote_target,
			    0);
			if (error) {
				free(remote_refname);
				free(remote_target);
				if (error->code == GOT_ERR_NOT_REF) {
					error = NULL;
					continue;
				}
				goto done;
			}
			error = update_symref(remote_refname, target_ref,
			    verbosity, repo);
			free(remote_refname);
			free(remote_target);
			got_ref_close(target_ref);
			if (error)
				goto done;
		}
	}
done:
	if (fetchpid > 0) {
		if (kill(fetchpid, SIGTERM) == -1)
			error = got_error_from_errno("kill");
		if (waitpid(fetchpid, &fetchstatus, 0) == -1 && error == NULL)
			error = got_error_from_errno("waitpid");
	}
	if (fetchfd != -1 && close(fetchfd) == -1 && error == NULL)
		error = got_error_from_errno("close");
	if (repo)
		got_repo_close(repo);
	if (worktree)
		got_worktree_close(worktree);
	TAILQ_FOREACH(pe, &refs, entry) {
		free((void *)pe->path);
		free(pe->data);
	}
	got_pathlist_free(&refs);
	TAILQ_FOREACH(pe, &symrefs, entry) {
		free((void *)pe->path);
		free(pe->data);
	}
	got_pathlist_free(&symrefs);
	got_pathlist_free(&wanted_branches);
	got_pathlist_free(&wanted_refs);
	free(id_str);
	free(cwd);
	free(repo_path);
	free(pack_hash);
	free(proto);
	free(host);
	free(port);
	free(server_path);
	free(repo_name);
	return error;
}


__dead static void
usage_checkout(void)
{
	fprintf(stderr, "usage: %s checkout [-E] [-b branch] [-c commit] "
	    "[-p prefix] repository-path [worktree-path]\n", getprogname());
	exit(1);
}

static void
show_worktree_base_ref_warning(void)
{
	fprintf(stderr, "%s: warning: could not create a reference "
	    "to the work tree's base commit; the commit could be "
	    "garbage-collected by Git; making the repository "
	    "writable and running 'got update' will prevent this\n",
	    getprogname());
}

struct got_checkout_progress_arg {
	const char *worktree_path;
	int had_base_commit_ref_error;
};

static const struct got_error *
checkout_progress(void *arg, unsigned char status, const char *path)
{
	struct got_checkout_progress_arg *a = arg;

	/* Base commit bump happens silently. */
	if (status == GOT_STATUS_BUMP_BASE)
		return NULL;

	if (status == GOT_STATUS_BASE_REF_ERR) {
		a->had_base_commit_ref_error = 1;
		return NULL;
	}

	while (path[0] == '/')
		path++;

	printf("%c  %s/%s\n", status, a->worktree_path, path);
	return NULL;
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
    struct got_object_id *base_commit_id, int allow_forwards_in_time_only,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object_id *yca_id;

	err = got_commit_graph_find_youngest_common_ancestor(&yca_id,
	    commit_id, base_commit_id, repo, check_cancelled, NULL);
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
	if (allow_forwards_in_time_only) {
	    if (got_object_id_cmp(base_commit_id, yca_id) != 0)
		return got_error(GOT_ERR_ANCESTRY);
	} else if (got_object_id_cmp(commit_id, yca_id) != 0 &&
	    got_object_id_cmp(base_commit_id, yca_id) != 0)
		return got_error(GOT_ERR_ANCESTRY);

	free(yca_id);
	return NULL;
}

static const struct got_error *
check_same_branch(struct got_object_id *commit_id,
    struct got_reference *head_ref, struct got_object_id *yca_id,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_commit_graph *graph = NULL;
	struct got_object_id *head_commit_id = NULL;
	int is_same_branch = 0;

	err = got_ref_resolve(&head_commit_id, repo, head_ref);
	if (err)
		goto done;

	if (got_object_id_cmp(head_commit_id, commit_id) == 0) {
		is_same_branch = 1;
		goto done;
	}
	if (yca_id && got_object_id_cmp(commit_id, yca_id) == 0) {
		is_same_branch = 1;
		goto done;
	}

	err = got_commit_graph_open(&graph, "/", 1);
	if (err)
		goto done;

	err = got_commit_graph_iter_start(graph, head_commit_id, repo,
	    check_cancelled, NULL);
	if (err)
		goto done;

	for (;;) {
		struct got_object_id *id;
		err = got_commit_graph_iter_next(&id, graph, repo,
		    check_cancelled, NULL);
		if (err) {
			if (err->code == GOT_ERR_ITER_COMPLETED)
				err = NULL;
			break;
		}

		if (id) {
			if (yca_id && got_object_id_cmp(id, yca_id) == 0)
				break;
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
checkout_ancestry_error(struct got_reference *ref, const char *commit_id_str)
{
	static char msg[512];
	const char *branch_name;

	if (got_ref_is_symbolic(ref))
		branch_name = got_ref_get_symref_target(ref);
	else
		branch_name = got_ref_get_name(ref);

	if (strncmp("refs/heads/", branch_name, 11) == 0)
		branch_name += 11;

	snprintf(msg, sizeof(msg),
	    "target commit is not contained in branch '%s'; "
	    "the branch to use must be specified with -b; "
	    "if necessary a new branch can be created for "
	    "this commit with 'got branch -c %s BRANCH_NAME'",
	    branch_name, commit_id_str);

	return got_error_msg(GOT_ERR_ANCESTRY, msg);
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
	char *cwd = NULL;
	int ch, same_path_prefix, allow_nonempty = 0;
	struct got_pathlist_head paths;
	struct got_checkout_progress_arg cpa;

	TAILQ_INIT(&paths);

	while ((ch = getopt(argc, argv, "b:c:Ep:")) != -1) {
		switch (ch) {
		case 'b':
			branch_name = optarg;
			break;
		case 'c':
			commit_id_str = strdup(optarg);
			if (commit_id_str == NULL)
				return got_error_from_errno("strdup");
			break;
		case 'E':
			allow_nonempty = 1;
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
		char *base, *dotgit;
		const char *path;
		repo_path = realpath(argv[0], NULL);
		if (repo_path == NULL)
			return got_error_from_errno2("realpath", argv[0]);
		cwd = getcwd(NULL, 0);
		if (cwd == NULL) {
			error = got_error_from_errno("getcwd");
			goto done;
		}
		if (path_prefix[0])
			path = path_prefix;
		else
			path = repo_path;
		error = got_path_basename(&base, path);
		if (error)
			goto done;
		dotgit = strstr(base, ".git");
		if (dotgit)
			*dotgit = '\0';
		if (asprintf(&worktree_path, "%s/%s", cwd, base) == -1) {
			error = got_error_from_errno("asprintf");
			free(base);
			goto done;
		}
		free(base);
	} else if (argc == 2) {
		repo_path = realpath(argv[0], NULL);
		if (repo_path == NULL) {
			error = got_error_from_errno2("realpath", argv[0]);
			goto done;
		}
		worktree_path = realpath(argv[1], NULL);
		if (worktree_path == NULL) {
			if (errno != ENOENT) {
				error = got_error_from_errno2("realpath",
				    argv[1]);
				goto done;
			}
			worktree_path = strdup(argv[1]);
			if (worktree_path == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		}
	} else
		usage_checkout();

	got_path_strip_trailing_slashes(repo_path);
	got_path_strip_trailing_slashes(worktree_path);

	error = got_repo_open(&repo, repo_path, NULL);
	if (error != NULL)
		goto done;

	/* Pre-create work tree path for unveil(2) */
	error = got_path_mkdir(worktree_path);
	if (error) {
		if (!(error->code == GOT_ERR_ERRNO && errno == EISDIR) &&
		    !(error->code == GOT_ERR_ERRNO && errno == EEXIST))
			goto done;
		if (!allow_nonempty &&
		    !got_path_dir_is_empty(worktree_path)) {
			error = got_error_path(worktree_path,
			    GOT_ERR_DIR_NOT_EMPTY);
			goto done;
		}
	}

	error = apply_unveil(got_repo_get_path(repo), 0, worktree_path);
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
		error = got_repo_match_object_id(&commit_id, NULL,
		    commit_id_str, GOT_OBJ_TYPE_COMMIT, 1, repo);
		if (error)
			goto done;
		error = check_linear_ancestry(commit_id,
		    got_worktree_get_base_commit_id(worktree), 0, repo);
		if (error != NULL) {
			free(commit_id);
			if (error->code == GOT_ERR_ANCESTRY) {
				error = checkout_ancestry_error(
				    head_ref, commit_id_str);
			}
			goto done;
		}
		error = check_same_branch(commit_id, head_ref, NULL, repo);
		if (error) {
			if (error->code == GOT_ERR_ANCESTRY) {
				error = checkout_ancestry_error(
				    head_ref, commit_id_str);
			}
			goto done;
		}
		error = got_worktree_set_base_commit_id(worktree, repo,
		    commit_id);
		free(commit_id);
		if (error)
			goto done;
	}

	error = got_pathlist_append(&paths, "", NULL);
	if (error)
		goto done;
	cpa.worktree_path = worktree_path;
	cpa.had_base_commit_ref_error = 0;
	error = got_worktree_checkout_files(worktree, &paths, repo,
	    checkout_progress, &cpa, check_cancelled, NULL);
	if (error != NULL)
		goto done;

	printf("Now shut up and hack\n");
	if (cpa.had_base_commit_ref_error)
		show_worktree_base_ref_warning();
done:
	got_pathlist_free(&paths);
	free(commit_id_str);
	free(repo_path);
	free(worktree_path);
	free(cwd);
	return error;
}

struct got_update_progress_arg {
	int did_something;
	int conflicts;
	int obstructed;
	int not_updated;
};

void
print_update_progress_stats(struct got_update_progress_arg *upa)
{
	if (!upa->did_something)
		return;

	if (upa->conflicts > 0)
		printf("Files with new merge conflicts: %d\n", upa->conflicts);
	if (upa->obstructed > 0)
		printf("File paths obstructed by a non-regular file: %d\n",
		    upa->obstructed);
	if (upa->not_updated > 0)
		printf("Files not updated because of existing merge "
		    "conflicts: %d\n", upa->not_updated);
}

__dead static void
usage_update(void)
{
	fprintf(stderr, "usage: %s update [-b branch] [-c commit] [path ...]\n",
	    getprogname());
	exit(1);
}

static const struct got_error *
update_progress(void *arg, unsigned char status, const char *path)
{
	struct got_update_progress_arg *upa = arg;

	if (status == GOT_STATUS_EXISTS ||
	    status == GOT_STATUS_BASE_REF_ERR)
		return NULL;

	upa->did_something = 1;

	/* Base commit bump happens silently. */
	if (status == GOT_STATUS_BUMP_BASE)
		return NULL;

	if (status == GOT_STATUS_CONFLICT)
		upa->conflicts++;
	if (status == GOT_STATUS_OBSTRUCTED)
		upa->obstructed++;
	if (status == GOT_STATUS_CANNOT_UPDATE)
		upa->not_updated++;

	while (path[0] == '/')
		path++;
	printf("%c  %s\n", status, path);
	return NULL;
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
	    got_worktree_get_base_commit_id(worktree), 0, repo);
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
check_rebase_or_histedit_in_progress(struct got_worktree *worktree)
{
	const struct got_error *err;
	int in_progress;

	err = got_worktree_rebase_in_progress(&in_progress, worktree);
	if (err)
		return err;
	if (in_progress)
		return got_error(GOT_ERR_REBASING);

	err = got_worktree_histedit_in_progress(&in_progress, worktree);
	if (err)
		return err;
	if (in_progress)
		return got_error(GOT_ERR_HISTEDIT_BUSY);

	return NULL;
}

static const struct got_error *
get_worktree_paths_from_argv(struct got_pathlist_head *paths, int argc,
    char *argv[], struct got_worktree *worktree)
{
	const struct got_error *err = NULL;
	char *path;
	int i;

	if (argc == 0) {
		path = strdup("");
		if (path == NULL)
			return got_error_from_errno("strdup");
		return got_pathlist_append(paths, path, NULL);
	}

	for (i = 0; i < argc; i++) {
		err = got_worktree_resolve_path(&path, worktree, argv[i]);
		if (err)
			break;
		err = got_pathlist_append(paths, path, NULL);
		if (err) {
			free(path);
			break;
		}
	}

	return err;
}

static const struct got_error *
wrap_not_worktree_error(const struct got_error *orig_err,
    const char *cmdname, const char *path)
{
	const struct got_error *err;
	struct got_repository *repo;
	static char msg[512];

	err = got_repo_open(&repo, path, NULL);
	if (err)
		return orig_err;

	snprintf(msg, sizeof(msg),
	    "'got %s' needs a work tree in addition to a git repository\n"
	    "Work trees can be checked out from this Git repository with "
	    "'got checkout'.\n"
	    "The got(1) manual page contains more information.", cmdname);
	err = got_error_msg(GOT_ERR_NOT_WORKTREE, msg);
	got_repo_close(repo);
	return err;
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
	const char *branch_name = NULL;
	struct got_reference *head_ref = NULL;
	struct got_pathlist_head paths;
	struct got_pathlist_entry *pe;
	int ch;
	struct got_update_progress_arg upa;

	TAILQ_INIT(&paths);

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
	if (error) {
		if (error->code == GOT_ERR_NOT_WORKTREE)
			error = wrap_not_worktree_error(error, "update",
			    worktree_path);
		goto done;
	}

	error = check_rebase_or_histedit_in_progress(worktree);
	if (error)
		goto done;

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree),
	    NULL);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 0,
	    got_worktree_get_root_path(worktree));
	if (error)
		goto done;

	error = get_worktree_paths_from_argv(&paths, argc, argv, worktree);
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
		error = got_repo_match_object_id(&commit_id, NULL,
		    commit_id_str, GOT_OBJ_TYPE_COMMIT, 1, repo);
		free(commit_id_str);
		commit_id_str = NULL;
		if (error)
			goto done;
		error = got_object_id_str(&commit_id_str, commit_id);
		if (error)
			goto done;
	}

	if (branch_name) {
		struct got_object_id *head_commit_id;
		TAILQ_FOREACH(pe, &paths, entry) {
			if (pe->path_len == 0)
				continue;
			error = got_error_msg(GOT_ERR_BAD_PATH,
			    "switching between branches requires that "
			    "the entire work tree gets updated");
			goto done;
		}
		error = got_ref_resolve(&head_commit_id, repo, head_ref);
		if (error)
			goto done;
		error = check_linear_ancestry(commit_id, head_commit_id, 0,
		    repo);
		free(head_commit_id);
		if (error != NULL)
			goto done;
		error = check_same_branch(commit_id, head_ref, NULL, repo);
		if (error)
			goto done;
		error = switch_head_ref(head_ref, commit_id, worktree, repo);
		if (error)
			goto done;
	} else {
		error = check_linear_ancestry(commit_id,
		    got_worktree_get_base_commit_id(worktree), 0, repo);
		if (error != NULL) {
			if (error->code == GOT_ERR_ANCESTRY)
				error = got_error(GOT_ERR_BRANCH_MOVED);
			goto done;
		}
		error = check_same_branch(commit_id, head_ref, NULL, repo);
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

	memset(&upa, 0, sizeof(upa));
	error = got_worktree_checkout_files(worktree, &paths, repo,
	    update_progress, &upa, check_cancelled, NULL);
	if (error != NULL)
		goto done;

	if (upa.did_something)
		printf("Updated to commit %s\n", commit_id_str);
	else
		printf("Already up-to-date\n");
	print_update_progress_stats(&upa);
done:
	free(worktree_path);
	TAILQ_FOREACH(pe, &paths, entry)
		free((char *)pe->path);
	got_pathlist_free(&paths);
	free(commit_id);
	free(commit_id_str);
	return error;
}

static const struct got_error *
diff_blobs(struct got_object_id *blob_id1, struct got_object_id *blob_id2,
    const char *path, int diff_context, int ignore_whitespace,
    int force_text_diff, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_blob_object *blob1 = NULL, *blob2 = NULL;

	if (blob_id1) {
		err = got_object_open_as_blob(&blob1, repo, blob_id1, 8192);
		if (err)
			goto done;
	}

	err = got_object_open_as_blob(&blob2, repo, blob_id2, 8192);
	if (err)
		goto done;

	while (path[0] == '/')
		path++;
	err = got_diff_blob(NULL, NULL, blob1, blob2, path, path,
	    diff_context, ignore_whitespace, force_text_diff, stdout);
done:
	if (blob1)
		got_object_blob_close(blob1);
	got_object_blob_close(blob2);
	return err;
}

static const struct got_error *
diff_trees(struct got_object_id *tree_id1, struct got_object_id *tree_id2,
    const char *path, int diff_context, int ignore_whitespace,
    int force_text_diff, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_tree_object *tree1 = NULL, *tree2 = NULL;
	struct got_diff_blob_output_unidiff_arg arg;

	if (tree_id1) {
		err = got_object_open_as_tree(&tree1, repo, tree_id1);
		if (err)
			goto done;
	}

	err = got_object_open_as_tree(&tree2, repo, tree_id2);
	if (err)
		goto done;

	arg.diff_context = diff_context;
	arg.ignore_whitespace = ignore_whitespace;
	arg.force_text_diff = force_text_diff;
	arg.outfile = stdout;
	arg.line_offsets = NULL;
	arg.nlines = 0;
	while (path[0] == '/')
		path++;
	err = got_diff_tree(tree1, tree2, path, path, repo,
	    got_diff_blob_output_unidiff, &arg, 1);
done:
	if (tree1)
		got_object_tree_close(tree1);
	if (tree2)
		got_object_tree_close(tree2);
	return err;
}

static const struct got_error *
get_changed_paths(struct got_pathlist_head *paths,
    struct got_commit_object *commit, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object_id *tree_id1 = NULL, *tree_id2 = NULL;
	struct got_tree_object *tree1 = NULL, *tree2 = NULL;
	struct got_object_qid *qid;

	qid = SIMPLEQ_FIRST(got_object_commit_get_parent_ids(commit));
	if (qid != NULL) {
		struct got_commit_object *pcommit;
		err = got_object_open_as_commit(&pcommit, repo,
		    qid->id);
		if (err)
			return err;

		tree_id1 = got_object_commit_get_tree_id(pcommit);
		got_object_commit_close(pcommit);

	}

	if (tree_id1) {
		err = got_object_open_as_tree(&tree1, repo, tree_id1);
		if (err)
			goto done;
	}

	tree_id2 = got_object_commit_get_tree_id(commit);
	err = got_object_open_as_tree(&tree2, repo, tree_id2);
	if (err)
		goto done;

	err = got_diff_tree(tree1, tree2, "", "", repo,
	    got_diff_tree_collect_changed_paths, paths, 0);
done:
	if (tree1)
		got_object_tree_close(tree1);
	if (tree2)
		got_object_tree_close(tree2);
	return err;
}

static const struct got_error *
print_patch(struct got_commit_object *commit, struct got_object_id *id,
    const char *path, int diff_context, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_commit_object *pcommit = NULL;
	char *id_str1 = NULL, *id_str2 = NULL;
	struct got_object_id *obj_id1 = NULL, *obj_id2 = NULL;
	struct got_object_qid *qid;

	qid = SIMPLEQ_FIRST(got_object_commit_get_parent_ids(commit));
	if (qid != NULL) {
		err = got_object_open_as_commit(&pcommit, repo,
		    qid->id);
		if (err)
			return err;
	}

	if (path && path[0] != '\0') {
		int obj_type;
		err = got_object_id_by_path(&obj_id2, repo, id, path);
		if (err)
			goto done;
		err = got_object_id_str(&id_str2, obj_id2);
		if (err) {
			free(obj_id2);
			goto done;
		}
		if (pcommit) {
			err = got_object_id_by_path(&obj_id1, repo,
			    qid->id, path);
			if (err) {
				if (err->code != GOT_ERR_NO_TREE_ENTRY) {
					free(obj_id2);
					goto done;
				}
			} else {
				err = got_object_id_str(&id_str1, obj_id1);
				if (err) {
					free(obj_id2);
					goto done;
				}
			}
		}
		err = got_object_get_type(&obj_type, repo, obj_id2);
		if (err) {
			free(obj_id2);
			goto done;
		}
		printf("diff %s %s\n", id_str1 ? id_str1 : "/dev/null", id_str2);
		switch (obj_type) {
		case GOT_OBJ_TYPE_BLOB:
			err = diff_blobs(obj_id1, obj_id2, path, diff_context,
			    0, 0, repo);
			break;
		case GOT_OBJ_TYPE_TREE:
			err = diff_trees(obj_id1, obj_id2, path, diff_context,
			    0, 0, repo);
			break;
		default:
			err = got_error(GOT_ERR_OBJ_TYPE);
			break;
		}
		free(obj_id1);
		free(obj_id2);
	} else {
		obj_id2 = got_object_commit_get_tree_id(commit);
		err = got_object_id_str(&id_str2, obj_id2);
		if (err)
			goto done;
		if (pcommit) {
			obj_id1 = got_object_commit_get_tree_id(pcommit);
			err = got_object_id_str(&id_str1, obj_id1);
			if (err)
				goto done;
		}
		printf("diff %s %s\n", id_str1 ? id_str1 : "/dev/null",
		    id_str2);
		err = diff_trees(obj_id1, obj_id2, "", diff_context, 0, 0,
		    repo);
	}
done:
	free(id_str1);
	free(id_str2);
	if (pcommit)
		got_object_commit_close(pcommit);
	return err;
}

static char *
get_datestr(time_t *time, char *datebuf)
{
	struct tm mytm, *tm;
	char *p, *s;

	tm = gmtime_r(time, &mytm);
	if (tm == NULL)
		return NULL;
	s = asctime_r(tm, datebuf);
	if (s == NULL)
		return NULL;
	p = strchr(s, '\n');
	if (p)
		*p = '\0';
	return s;
}

static const struct got_error *
match_logmsg(int *have_match, struct got_object_id *id,
    struct got_commit_object *commit, regex_t *regex)
{
	const struct got_error *err = NULL;
	regmatch_t regmatch;
	char *id_str = NULL, *logmsg = NULL;

	*have_match = 0;

	err = got_object_id_str(&id_str, id);
	if (err)
		return err;

	err = got_object_commit_get_logmsg(&logmsg, commit);
	if (err)
		goto done;

	if (regexec(regex, logmsg, 1, &regmatch, 0) == 0)
		*have_match = 1;
done:
	free(id_str);
	free(logmsg);
	return err;
}

static void
match_changed_paths(int *have_match, struct got_pathlist_head *changed_paths,
    regex_t *regex)
{
	regmatch_t regmatch;
	struct got_pathlist_entry *pe;

	*have_match = 0;

	TAILQ_FOREACH(pe, changed_paths, entry) {
		if (regexec(regex, pe->path, 1, &regmatch, 0) == 0) {
			*have_match = 1;
			break;
		}
	}
}

#define GOT_COMMIT_SEP_STR "-----------------------------------------------\n"

static const struct got_error *
print_commit(struct got_commit_object *commit, struct got_object_id *id,
    struct got_repository *repo, const char *path,
    struct got_pathlist_head *changed_paths, int show_patch,
    int diff_context, struct got_reflist_head *refs)
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
		struct got_tag_object *tag = NULL;
		struct got_object_id *ref_id;
		int cmp;

		name = got_ref_get_name(re->ref);
		if (strcmp(name, GOT_REF_HEAD) == 0)
			continue;
		if (strncmp(name, "refs/", 5) == 0)
			name += 5;
		if (strncmp(name, "got/", 4) == 0)
			continue;
		if (strncmp(name, "heads/", 6) == 0)
			name += 6;
		if (strncmp(name, "remotes/", 8) == 0) {
			name += 8;
			s = strstr(name, "/" GOT_REF_HEAD);
			if (s != NULL && s[strlen(s)] == '\0')
				continue;
		}
		err = got_ref_resolve(&ref_id, repo, re->ref);
		if (err)
			return err;
		if (strncmp(name, "tags/", 5) == 0) {
			err = got_object_open_as_tag(&tag, repo, ref_id);
			if (err) {
				if (err->code != GOT_ERR_OBJ_TYPE) {
					free(ref_id);
					return err;
				}
				/* Ref points at something other than a tag. */
				err = NULL;
				tag = NULL;
			}
		}
		cmp = got_object_id_cmp(tag ?
		    got_object_tag_get_object_id(tag) : ref_id, id);
		free(ref_id);
		if (tag)
			got_object_tag_close(tag);
		if (cmp != 0)
			continue;
		s = refs_str;
		if (asprintf(&refs_str, "%s%s%s", s ? s : "", s ? ", " : "",
		    name) == -1) {
			err = got_error_from_errno("asprintf");
			free(s);
			return err;
		}
		free(s);
	}
	err = got_object_id_str(&id_str, id);
	if (err)
		return err;

	printf(GOT_COMMIT_SEP_STR);
	printf("commit %s%s%s%s\n", id_str, refs_str ? " (" : "",
	    refs_str ? refs_str : "", refs_str ? ")" : "");
	free(id_str);
	id_str = NULL;
	free(refs_str);
	refs_str = NULL;
	printf("from: %s\n", got_object_commit_get_author(commit));
	committer_time = got_object_commit_get_committer_time(commit);
	datestr = get_datestr(&committer_time, datebuf);
	if (datestr)
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

	err = got_object_commit_get_logmsg(&logmsg0, commit);
	if (err)
		return err;

	logmsg = logmsg0;
	do {
		line = strsep(&logmsg, "\n");
		if (line)
			printf(" %s\n", line);
	} while (line);
	free(logmsg0);

	if (changed_paths) {
		struct got_pathlist_entry *pe;
		TAILQ_FOREACH(pe, changed_paths, entry) {
			struct got_diff_changed_path *cp = pe->data;
			printf(" %c  %s\n", cp->status, pe->path);
		}
		printf("\n");
	}
	if (show_patch) {
		err = print_patch(commit, id, path, diff_context, repo);
		if (err == 0)
			printf("\n");
	}

	if (fflush(stdout) != 0 && err == NULL)
		err = got_error_from_errno("fflush");
	return err;
}

static const struct got_error *
print_commits(struct got_object_id *root_id, struct got_object_id *end_id,
    struct got_repository *repo, const char *path, int show_changed_paths,
    int show_patch, const char *search_pattern, int diff_context, int limit,
    int log_branches, int reverse_display_order, struct got_reflist_head *refs)
{
	const struct got_error *err;
	struct got_commit_graph *graph;
	regex_t regex;
	int have_match;
	struct got_object_id_queue reversed_commits;
	struct got_object_qid *qid;
	struct got_commit_object *commit;
	struct got_pathlist_head changed_paths;
	struct got_pathlist_entry *pe;

	SIMPLEQ_INIT(&reversed_commits);
	TAILQ_INIT(&changed_paths);

	if (search_pattern && regcomp(&regex, search_pattern,
	    REG_EXTENDED | REG_NOSUB | REG_NEWLINE))
		return got_error_msg(GOT_ERR_REGEX, search_pattern);

	err = got_commit_graph_open(&graph, path, !log_branches);
	if (err)
		return err;
	err = got_commit_graph_iter_start(graph, root_id, repo,
	    check_cancelled, NULL);
	if (err)
		goto done;
	for (;;) {
		struct got_object_id *id;

		if (sigint_received || sigpipe_received)
			break;

		err = got_commit_graph_iter_next(&id, graph, repo,
		    check_cancelled, NULL);
		if (err) {
			if (err->code == GOT_ERR_ITER_COMPLETED)
				err = NULL;
			break;
		}
		if (id == NULL)
			break;

		err = got_object_open_as_commit(&commit, repo, id);
		if (err)
			break;

		if (show_changed_paths && !reverse_display_order) {
			err = get_changed_paths(&changed_paths, commit, repo);
			if (err)
				break;
		}

		if (search_pattern) {
			err = match_logmsg(&have_match, id, commit, &regex);
			if (err) {
				got_object_commit_close(commit);
				break;
			}
			if (have_match == 0 && show_changed_paths)
				match_changed_paths(&have_match,
				    &changed_paths, &regex);
			if (have_match == 0) {
				got_object_commit_close(commit);
				TAILQ_FOREACH(pe, &changed_paths, entry) {
					free((char *)pe->path);
					free(pe->data);
				}
				got_pathlist_free(&changed_paths);
				continue;
			}
		}

		if (reverse_display_order) {
			err = got_object_qid_alloc(&qid, id);
			if (err)
				break;
			SIMPLEQ_INSERT_HEAD(&reversed_commits, qid, entry);
			got_object_commit_close(commit);
		} else {
			err = print_commit(commit, id, repo, path,
			    show_changed_paths ? &changed_paths : NULL,
			    show_patch, diff_context, refs);
			got_object_commit_close(commit);
			if (err)
				break;
		}
		if ((limit && --limit == 0) ||
		    (end_id && got_object_id_cmp(id, end_id) == 0))
			break;

		TAILQ_FOREACH(pe, &changed_paths, entry) {
			free((char *)pe->path);
			free(pe->data);
		}
		got_pathlist_free(&changed_paths);
	}
	if (reverse_display_order) {
		SIMPLEQ_FOREACH(qid, &reversed_commits, entry) {
			err = got_object_open_as_commit(&commit, repo, qid->id);
			if (err)
				break;
			if (show_changed_paths) {
				err = get_changed_paths(&changed_paths,
				    commit, repo);
				if (err)
					break;
			}
			err = print_commit(commit, qid->id, repo, path,
			    show_changed_paths ? &changed_paths : NULL,
			    show_patch, diff_context, refs);
			got_object_commit_close(commit);
			if (err)
				break;
			TAILQ_FOREACH(pe, &changed_paths, entry) {
				free((char *)pe->path);
				free(pe->data);
			}
			got_pathlist_free(&changed_paths);
		}
	}
done:
	while (!SIMPLEQ_EMPTY(&reversed_commits)) {
		qid = SIMPLEQ_FIRST(&reversed_commits);
		SIMPLEQ_REMOVE_HEAD(&reversed_commits, entry);
		got_object_qid_free(qid);
	}
	TAILQ_FOREACH(pe, &changed_paths, entry) {
		free((char *)pe->path);
		free(pe->data);
	}
	got_pathlist_free(&changed_paths);
	if (search_pattern)
		regfree(&regex);
	got_commit_graph_close(graph);
	return err;
}

__dead static void
usage_log(void)
{
	fprintf(stderr, "usage: %s log [-b] [-c commit] [-C number] [ -l N ] "
	    "[-p] [-P] [-x commit] [-s search-pattern] [-r repository-path] "
	    "[-R] [path]\n", getprogname());
	exit(1);
}

static int
get_default_log_limit(void)
{
	const char *got_default_log_limit;
	long long n;
	const char *errstr;

	got_default_log_limit = getenv("GOT_LOG_DEFAULT_LIMIT");
	if (got_default_log_limit == NULL)
		return 0;
	n = strtonum(got_default_log_limit, 0, INT_MAX, &errstr);
	if (errstr != NULL)
		return 0;
	return n;
}

static const struct got_error *
cmd_log(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	struct got_object_id *start_id = NULL, *end_id = NULL;
	char *repo_path = NULL, *path = NULL, *cwd = NULL, *in_repo_path = NULL;
	const char *start_commit = NULL, *end_commit = NULL;
	const char *search_pattern = NULL;
	int diff_context = -1, ch;
	int show_changed_paths = 0, show_patch = 0, limit = 0, log_branches = 0;
	int reverse_display_order = 0;
	const char *errstr;
	struct got_reflist_head refs;

	SIMPLEQ_INIT(&refs);

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc exec sendfd unveil",
	    NULL)
	    == -1)
		err(1, "pledge");
#endif

	limit = get_default_log_limit();

	while ((ch = getopt(argc, argv, "bpPc:C:l:r:Rs:x:")) != -1) {
		switch (ch) {
		case 'p':
			show_patch = 1;
			break;
		case 'P':
			show_changed_paths = 1;
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
			limit = strtonum(optarg, 0, INT_MAX, &errstr);
			if (errstr != NULL)
				err(1, "-l option %s", errstr);
			break;
		case 'b':
			log_branches = 1;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				return got_error_from_errno2("realpath",
				    optarg);
			got_path_strip_trailing_slashes(repo_path);
			break;
		case 'R':
			reverse_display_order = 1;
			break;
		case 's':
			search_pattern = optarg;
			break;
		case 'x':
			end_commit = optarg;
			break;
		default:
			usage_log();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (diff_context == -1)
		diff_context = 3;
	else if (!show_patch)
		errx(1, "-C requires -p");

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	if (repo_path == NULL) {
		error = got_worktree_open(&worktree, cwd);
		if (error && error->code != GOT_ERR_NOT_WORKTREE)
			goto done;
		error = NULL;
	}

	if (argc == 1) {
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
	} else if (argc != 0)
		usage_log();

	if (repo_path == NULL) {
		repo_path = worktree ?
		    strdup(got_worktree_get_repo_path(worktree)) : strdup(cwd);
	}
	if (repo_path == NULL) {
		error = got_error_from_errno("strdup");
		goto done;
	}

	error = got_repo_open(&repo, repo_path, NULL);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 1,
	    worktree ? got_worktree_get_root_path(worktree) : NULL);
	if (error)
		goto done;

	if (start_commit == NULL) {
		struct got_reference *head_ref;
		struct got_commit_object *commit = NULL;
		error = got_ref_open(&head_ref, repo,
		    worktree ? got_worktree_get_head_ref_name(worktree)
		    : GOT_REF_HEAD, 0);
		if (error != NULL)
			goto done;
		error = got_ref_resolve(&start_id, repo, head_ref);
		got_ref_close(head_ref);
		if (error != NULL)
			goto done;
		error = got_object_open_as_commit(&commit, repo,
		    start_id);
		if (error != NULL)
			goto done;
		got_object_commit_close(commit);
	} else {
		error = got_repo_match_object_id(&start_id, NULL,
		    start_commit, GOT_OBJ_TYPE_COMMIT, 1, repo);
		if (error != NULL)
			goto done;
	}
	if (end_commit != NULL) {
		error = got_repo_match_object_id(&end_id, NULL,
		    end_commit, GOT_OBJ_TYPE_COMMIT, 1, repo);
		if (error != NULL)
			goto done;
	}

	if (worktree) {
		/*
		 * If a path was specified on the command line it was resolved
		 * to a path in the work tree above. Prepend the work tree's
		 * path prefix to obtain the corresponding in-repository path.
		 */
		if (path) {
			const char *prefix;
			prefix = got_worktree_get_path_prefix(worktree);
			if (asprintf(&in_repo_path, "%s%s%s", prefix,
			    (path[0] != '\0') ? "/" : "", path) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}
		}
	} else
		error = got_repo_map_path(&in_repo_path, repo,
		    path ? path : "");
	if (error != NULL)
		goto done;
	if (in_repo_path) {
		free(path);
		path = in_repo_path;
	}

	error = got_ref_list(&refs, repo, NULL, got_ref_cmp_by_name, NULL);
	if (error)
		goto done;

	error = print_commits(start_id, end_id, repo, path ? path : "",
	    show_changed_paths, show_patch, search_pattern, diff_context,
	    limit, log_branches, reverse_display_order, &refs);
done:
	free(path);
	free(repo_path);
	free(cwd);
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
	fprintf(stderr, "usage: %s diff [-a] [-C number] [-r repository-path] "
	    "[-s] [-w] [object1 object2 | path]\n", getprogname());
	exit(1);
}

struct print_diff_arg {
	struct got_repository *repo;
	struct got_worktree *worktree;
	int diff_context;
	const char *id_str;
	int header_shown;
	int diff_staged;
	int ignore_whitespace;
	int force_text_diff;
};

/*
 * Create a file which contains the target path of a symlink so we can feed
 * it as content to the diff engine.
 */
static const struct got_error *
get_symlink_target_file(int *fd, int dirfd, const char *de_name,
    const char *abspath)
{
	const struct got_error *err = NULL;
	char target_path[PATH_MAX];
	ssize_t target_len, outlen;

	*fd = -1;

	if (dirfd != -1) {
		target_len = readlinkat(dirfd, de_name, target_path, PATH_MAX);
		if (target_len == -1)
			return got_error_from_errno2("readlinkat", abspath);
	} else {
		target_len = readlink(abspath, target_path, PATH_MAX);
		if (target_len == -1)
			return got_error_from_errno2("readlink", abspath);
	}

	*fd = got_opentempfd();
	if (*fd == -1)
		return got_error_from_errno("got_opentempfd");

	outlen = write(*fd, target_path, target_len);
	if (outlen == -1) {
		err = got_error_from_errno("got_opentempfd");
		goto done;
	}

	if (lseek(*fd, 0, SEEK_SET) == -1) {
		err = got_error_from_errno2("lseek", abspath);
		goto done;
	}
done:
	if (err) {
		close(*fd);
		*fd = -1;
	}
	return err;
}

static const struct got_error *
print_diff(void *arg, unsigned char status, unsigned char staged_status,
    const char *path, struct got_object_id *blob_id,
    struct got_object_id *staged_blob_id, struct got_object_id *commit_id,
    int dirfd, const char *de_name)
{
	struct print_diff_arg *a = arg;
	const struct got_error *err = NULL;
	struct got_blob_object *blob1 = NULL;
	int fd = -1;
	FILE *f2 = NULL;
	char *abspath = NULL, *label1 = NULL;
	struct stat sb;

	if (a->diff_staged) {
		if (staged_status != GOT_STATUS_MODIFY &&
		    staged_status != GOT_STATUS_ADD &&
		    staged_status != GOT_STATUS_DELETE)
			return NULL;
	} else {
		if (staged_status == GOT_STATUS_DELETE)
			return NULL;
		if (status == GOT_STATUS_NONEXISTENT)
			return got_error_set_errno(ENOENT, path);
		if (status != GOT_STATUS_MODIFY &&
		    status != GOT_STATUS_ADD &&
		    status != GOT_STATUS_DELETE &&
		    status != GOT_STATUS_CONFLICT)
			return NULL;
	}

	if (!a->header_shown) {
		printf("diff %s %s%s\n", a->id_str,
		    got_worktree_get_root_path(a->worktree),
		    a->diff_staged ? " (staged changes)" : "");
		a->header_shown = 1;
	}

	if (a->diff_staged) {
		const char *label1 = NULL, *label2 = NULL;
		switch (staged_status) {
		case GOT_STATUS_MODIFY:
			label1 = path;
			label2 = path;
			break;
		case GOT_STATUS_ADD:
			label2 = path;
			break;
		case GOT_STATUS_DELETE:
			label1 = path;
			break;
		default:
			return got_error(GOT_ERR_FILE_STATUS);
		}
		return got_diff_objects_as_blobs(NULL, NULL, blob_id,
		    staged_blob_id, label1, label2, a->diff_context,
		    a->ignore_whitespace, a->force_text_diff, a->repo, stdout);
	}

	if (staged_status == GOT_STATUS_ADD ||
	    staged_status == GOT_STATUS_MODIFY) {
		char *id_str;
		err = got_object_open_as_blob(&blob1, a->repo, staged_blob_id,
		    8192);
		if (err)
			goto done;
		err = got_object_id_str(&id_str, staged_blob_id);
		if (err)
			goto done;
		if (asprintf(&label1, "%s (staged)", id_str) == -1) {
			err = got_error_from_errno("asprintf");
			free(id_str);
			goto done;
		}
		free(id_str);
	} else if (status != GOT_STATUS_ADD) {
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

		if (dirfd != -1) {
			fd = openat(dirfd, de_name, O_RDONLY | O_NOFOLLOW);
			if (fd == -1) {
				if (errno != ELOOP) {
					err = got_error_from_errno2("openat",
					    abspath);
					goto done;
				}
				err = get_symlink_target_file(&fd, dirfd,
				    de_name, abspath);
				if (err)
					goto done;
			}
		} else {
			fd = open(abspath, O_RDONLY | O_NOFOLLOW);
			if (fd == -1) {
				if (errno != ELOOP) {
					err = got_error_from_errno2("open",
					    abspath);
					goto done;
				}
				err = get_symlink_target_file(&fd, dirfd,
				    de_name, abspath);
				if (err)
					goto done;
			}
		}
		if (fstat(fd, &sb) == -1) {
			err = got_error_from_errno2("fstat", abspath);
			goto done;
		}
		f2 = fdopen(fd, "r");
		if (f2 == NULL) {
			err = got_error_from_errno2("fdopen", abspath);
			goto done;
		}
		fd = -1;
	} else
		sb.st_size = 0;

	err = got_diff_blob_file(blob1, label1, f2, sb.st_size, path,
	    a->diff_context, a->ignore_whitespace, a->force_text_diff, stdout);
done:
	if (blob1)
		got_object_blob_close(blob1);
	if (f2 && fclose(f2) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
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
	int diff_context = 3, diff_staged = 0, ignore_whitespace = 0, ch;
	int force_text_diff = 0;
	const char *errstr;
	char *path = NULL;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "aC:r:sw")) != -1) {
		switch (ch) {
		case 'a':
			force_text_diff = 1;
			break;
		case 'C':
			diff_context = strtonum(optarg, 0, GOT_DIFF_MAX_CONTEXT,
			    &errstr);
			if (errstr != NULL)
				err(1, "-C option %s", errstr);
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				return got_error_from_errno2("realpath",
				    optarg);
			got_path_strip_trailing_slashes(repo_path);
			break;
		case 's':
			diff_staged = 1;
			break;
		case 'w':
			ignore_whitespace = 1;
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
	if (argc <= 1) {
		if (repo_path)
			errx(1,
			    "-r option can't be used when diffing a work tree");
		error = got_worktree_open(&worktree, cwd);
		if (error) {
			if (error->code == GOT_ERR_NOT_WORKTREE)
				error = wrap_not_worktree_error(error, "diff",
				    cwd);
			goto done;
		}
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
		if (diff_staged)
			errx(1, "-s option can't be used when diffing "
			    "objects in repository");
		id_str1 = argv[0];
		id_str2 = argv[1];
		if (repo_path == NULL) {
			error = got_worktree_open(&worktree, cwd);
			if (error && error->code != GOT_ERR_NOT_WORKTREE)
				goto done;
			if (worktree) {
				repo_path = strdup(
				    got_worktree_get_repo_path(worktree));
				if (repo_path == NULL) {
					error = got_error_from_errno("strdup");
					goto done;
				}
			} else {
				repo_path = strdup(cwd);
				if (repo_path == NULL) {
					error = got_error_from_errno("strdup");
					goto done;
				}
			}
		}
	} else
		usage_diff();

	error = got_repo_open(&repo, repo_path, NULL);
	free(repo_path);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 1,
	    worktree ? got_worktree_get_root_path(worktree) : NULL);
	if (error)
		goto done;

	if (argc <= 1) {
		struct print_diff_arg arg;
		struct got_pathlist_head paths;
		char *id_str;

		TAILQ_INIT(&paths);

		error = got_object_id_str(&id_str,
		    got_worktree_get_base_commit_id(worktree));
		if (error)
			goto done;
		arg.repo = repo;
		arg.worktree = worktree;
		arg.diff_context = diff_context;
		arg.id_str = id_str;
		arg.header_shown = 0;
		arg.diff_staged = diff_staged;
		arg.ignore_whitespace = ignore_whitespace;
		arg.force_text_diff = force_text_diff;

		error = got_pathlist_append(&paths, path, NULL);
		if (error)
			goto done;

		error = got_worktree_status(worktree, &paths, repo, print_diff,
		    &arg, check_cancelled, NULL);
		free(id_str);
		got_pathlist_free(&paths);
		goto done;
	}

	error = got_repo_match_object_id(&id1, &label1, id_str1,
	    GOT_OBJ_TYPE_ANY, 1, repo);
	if (error)
		goto done;

	error = got_repo_match_object_id(&id2, &label2, id_str2,
	    GOT_OBJ_TYPE_ANY, 1, repo);
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
		error = got_diff_objects_as_blobs(NULL, NULL, id1, id2,
		    NULL, NULL, diff_context, ignore_whitespace,
		    force_text_diff, repo, stdout);
		break;
	case GOT_OBJ_TYPE_TREE:
		error = got_diff_objects_as_trees(NULL, NULL, id1, id2,
		    "", "", diff_context, ignore_whitespace, force_text_diff,
		    repo, stdout);
		break;
	case GOT_OBJ_TYPE_COMMIT:
		printf("diff %s %s\n", label1, label2);
		error = got_diff_objects_as_commits(NULL, NULL, id1, id2,
		    diff_context, ignore_whitespace, force_text_diff, repo,
		    stdout);
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

struct blame_line {
	int annotated;
	char *id_str;
	char *committer;
	char datebuf[11]; /* YYYY-MM-DD + NUL */
};

struct blame_cb_args {
	struct blame_line *lines;
	int nlines;
	int nlines_prec;
	int lineno_cur;
	off_t *line_offsets;
	FILE *f;
	struct got_repository *repo;
};

static const struct got_error *
blame_cb(void *arg, int nlines, int lineno, struct got_object_id *id)
{
	const struct got_error *err = NULL;
	struct blame_cb_args *a = arg;
	struct blame_line *bline;
	char *line = NULL;
	size_t linesize = 0;
	struct got_commit_object *commit = NULL;
	off_t offset;
	struct tm tm;
	time_t committer_time;

	if (nlines != a->nlines ||
	    (lineno != -1 && lineno < 1) || lineno > a->nlines)
		return got_error(GOT_ERR_RANGE);

	if (sigint_received)
		return got_error(GOT_ERR_ITER_COMPLETED);

	if (lineno == -1)
		return NULL; /* no change in this commit */

	/* Annotate this line. */
	bline = &a->lines[lineno - 1];
	if (bline->annotated)
		return NULL;
	err = got_object_id_str(&bline->id_str, id);
	if (err)
		return err;

	err = got_object_open_as_commit(&commit, a->repo, id);
	if (err)
		goto done;

	bline->committer = strdup(got_object_commit_get_committer(commit));
	if (bline->committer == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

	committer_time = got_object_commit_get_committer_time(commit);
	if (localtime_r(&committer_time, &tm) == NULL)
		return got_error_from_errno("localtime_r");
	if (strftime(bline->datebuf, sizeof(bline->datebuf), "%G-%m-%d",
	    &tm) >= sizeof(bline->datebuf)) {
		err = got_error(GOT_ERR_NO_SPACE);
		goto done;
	}
	bline->annotated = 1;

	/* Print lines annotated so far. */
	bline = &a->lines[a->lineno_cur - 1];
	if (!bline->annotated)
		goto done;

	offset = a->line_offsets[a->lineno_cur - 1];
	if (fseeko(a->f, offset, SEEK_SET) == -1) {
		err = got_error_from_errno("fseeko");
		goto done;
	}

	while (bline->annotated) {
		char *smallerthan, *at, *nl, *committer;
		size_t len;

		if (getline(&line, &linesize, a->f) == -1) {
			if (ferror(a->f))
				err = got_error_from_errno("getline");
			break;
		}

		committer = bline->committer;
		smallerthan = strchr(committer, '<');
		if (smallerthan && smallerthan[1] != '\0')
			committer = smallerthan + 1;
		at = strchr(committer, '@');
		if (at)
			*at = '\0';
		len = strlen(committer);
		if (len >= 9)
			committer[8] = '\0';

		nl = strchr(line, '\n');
		if (nl)
			*nl = '\0';
		printf("%.*d) %.8s %s %-8s %s\n", a->nlines_prec, a->lineno_cur,
		    bline->id_str, bline->datebuf, committer, line);

		a->lineno_cur++;
		bline = &a->lines[a->lineno_cur - 1];
	}
done:
	if (commit)
		got_object_commit_close(commit);
	free(line);
	return err;
}

static const struct got_error *
cmd_blame(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *path, *cwd = NULL, *repo_path = NULL, *in_repo_path = NULL;
	char *link_target = NULL;
	struct got_object_id *obj_id = NULL;
	struct got_object_id *commit_id = NULL;
	struct got_blob_object *blob = NULL;
	char *commit_id_str = NULL;
	struct blame_cb_args bca;
	int ch, obj_type, i;
	off_t filesize;

	memset(&bca, 0, sizeof(bca));

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
				return got_error_from_errno2("realpath",
				    optarg);
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
			if (repo_path == NULL) {
				error = got_error_from_errno("strdup");
				if (error)
					goto done;
			}
		} else {
			repo_path = strdup(cwd);
			if (repo_path == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		}
	}

	error = got_repo_open(&repo, repo_path, NULL);
	if (error != NULL)
		goto done;

	if (worktree) {
		const char *prefix = got_worktree_get_path_prefix(worktree);
		char *p;

		error = got_worktree_resolve_path(&p, worktree, path);
		if (error)
			goto done;
		if (asprintf(&in_repo_path, "%s%s%s", prefix,
		    (p[0] != '\0' && !got_path_is_root_dir(prefix)) ? "/" : "",
		    p) == -1) {
			error = got_error_from_errno("asprintf");
			free(p);
			goto done;
		}
		free(p);
		error = apply_unveil(got_repo_get_path(repo), 1, NULL);
	} else {
		error = apply_unveil(got_repo_get_path(repo), 1, NULL);
		if (error)
			goto done;
		error = got_repo_map_path(&in_repo_path, repo, path);
	}
	if (error)
		goto done;

	if (commit_id_str == NULL) {
		struct got_reference *head_ref;
		error = got_ref_open(&head_ref, repo, worktree ?
		    got_worktree_get_head_ref_name(worktree) : GOT_REF_HEAD, 0);
		if (error != NULL)
			goto done;
		error = got_ref_resolve(&commit_id, repo, head_ref);
		got_ref_close(head_ref);
		if (error != NULL)
			goto done;
	} else {
		error = got_repo_match_object_id(&commit_id, NULL,
		    commit_id_str, GOT_OBJ_TYPE_COMMIT, 1, repo);
		if (error)
			goto done;
	}

	error = got_object_resolve_symlinks(&link_target, in_repo_path,
	    commit_id, repo);
	if (error)
		goto done;

	error = got_object_id_by_path(&obj_id, repo, commit_id,
	    link_target ? link_target : in_repo_path);
	if (error)
		goto done;

	error = got_object_get_type(&obj_type, repo, obj_id);
	if (error)
		goto done;

	if (obj_type != GOT_OBJ_TYPE_BLOB) {
		error = got_error_path(link_target ? link_target : in_repo_path,
		    GOT_ERR_OBJ_TYPE);
		goto done;
	}

	error = got_object_open_as_blob(&blob, repo, obj_id, 8192);
	if (error)
		goto done;
	bca.f = got_opentemp();
	if (bca.f == NULL) {
		error = got_error_from_errno("got_opentemp");
		goto done;
	}
	error = got_object_blob_dump_to_file(&filesize, &bca.nlines,
	    &bca.line_offsets, bca.f, blob);
	if (error || bca.nlines == 0)
		goto done;

	/* Don't include \n at EOF in the blame line count. */
	if (bca.line_offsets[bca.nlines - 1] == filesize)
		bca.nlines--;

	bca.lines = calloc(bca.nlines, sizeof(*bca.lines));
	if (bca.lines == NULL) {
		error = got_error_from_errno("calloc");
		goto done;
	}
	bca.lineno_cur = 1;
	bca.nlines_prec = 0;
	i = bca.nlines;
	while (i > 0) {
		i /= 10;
		bca.nlines_prec++;
	}
	bca.repo = repo;

	error = got_blame(link_target ? link_target : in_repo_path, commit_id,
	    repo, blame_cb, &bca, check_cancelled, NULL);
done:
	free(in_repo_path);
	free(link_target);
	free(repo_path);
	free(cwd);
	free(commit_id);
	free(obj_id);
	if (blob)
		got_object_blob_close(blob);
	if (worktree)
		got_worktree_close(worktree);
	if (repo) {
		const struct got_error *repo_error;
		repo_error = got_repo_close(repo);
		if (error == NULL)
			error = repo_error;
	}
	if (bca.lines) {
		for (i = 0; i < bca.nlines; i++) {
			struct blame_line *bline = &bca.lines[i];
			free(bline->id_str);
			free(bline->committer);
		}
		free(bca.lines);
	}
	free(bca.line_offsets);
	if (bca.f && fclose(bca.f) == EOF && error == NULL)
		error = got_error_from_errno("fclose");
	return error;
}

__dead static void
usage_tree(void)
{
	fprintf(stderr,
	    "usage: %s tree [-c commit] [-r repository-path] [-iR] [path]\n",
	    getprogname());
	exit(1);
}

static const struct got_error *
print_entry(struct got_tree_entry *te, const char *id, const char *path,
    const char *root_path, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	int is_root_path = (strcmp(path, root_path) == 0);
	const char *modestr = "";
	mode_t mode = got_tree_entry_get_mode(te);
	char *link_target = NULL;

	path += strlen(root_path);
	while (path[0] == '/')
		path++;

	if (got_object_tree_entry_is_submodule(te))
		modestr = "$";
	else if (S_ISLNK(mode)) {
		int i;

		err = got_tree_entry_get_symlink_target(&link_target, te, repo);
		if (err)
			return err;
		for (i = 0; i < strlen(link_target); i++) {
			if (!isprint((unsigned char)link_target[i]))
				link_target[i] = '?';
		}

		modestr = "@";
	}
	else if (S_ISDIR(mode))
		modestr = "/";
	else if (mode & S_IXUSR)
		modestr = "*";

	printf("%s%s%s%s%s%s%s\n", id ? id : "", path,
	    is_root_path ? "" : "/", got_tree_entry_get_name(te), modestr,
	    link_target ? " -> ": "", link_target ? link_target : "");

	free(link_target);
	return NULL;
}

static const struct got_error *
print_tree(const char *path, struct got_object_id *commit_id,
    int show_ids, int recurse, const char *root_path,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object_id *tree_id = NULL;
	struct got_tree_object *tree = NULL;
	int nentries, i;

	err = got_object_id_by_path(&tree_id, repo, commit_id, path);
	if (err)
		goto done;

	err = got_object_open_as_tree(&tree, repo, tree_id);
	if (err)
		goto done;
	nentries = got_object_tree_get_nentries(tree);
	for (i = 0; i < nentries; i++) {
		struct got_tree_entry *te;
		char *id = NULL;

		if (sigint_received || sigpipe_received)
			break;

		te = got_object_tree_get_entry(tree, i);
		if (show_ids) {
			char *id_str;
			err = got_object_id_str(&id_str,
			    got_tree_entry_get_id(te));
			if (err)
				goto done;
			if (asprintf(&id, "%s ", id_str) == -1) {
				err = got_error_from_errno("asprintf");
				free(id_str);
				goto done;
			}
			free(id_str);
		}
		err = print_entry(te, id, path, root_path, repo);
		free(id);
		if (err)
			goto done;

		if (recurse && S_ISDIR(got_tree_entry_get_mode(te))) {
			char *child_path;
			if (asprintf(&child_path, "%s%s%s", path,
			    path[0] == '/' && path[1] == '\0' ? "" : "/",
			    got_tree_entry_get_name(te)) == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}
			err = print_tree(child_path, commit_id, show_ids, 1,
			    root_path, repo);
			free(child_path);
			if (err)
				goto done;
		}
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
	const char *path, *refname = NULL;
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
				return got_error_from_errno2("realpath",
				    optarg);
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

	error = got_repo_open(&repo, repo_path, NULL);
	if (error != NULL)
		goto done;

	if (worktree) {
		const char *prefix = got_worktree_get_path_prefix(worktree);
		char *p;

		if (path == NULL)
			path = "";
		error = got_worktree_resolve_path(&p, worktree, path);
		if (error)
			goto done;
		if (asprintf(&in_repo_path, "%s%s%s", prefix,
		    (p[0] != '\0' && !got_path_is_root_dir(prefix)) ?  "/" : "",
		    p) == -1) {
			error = got_error_from_errno("asprintf");
			free(p);
			goto done;
		}
		free(p);
		error = apply_unveil(got_repo_get_path(repo), 1, NULL);
		if (error)
			goto done;
	} else {
		error = apply_unveil(got_repo_get_path(repo), 1, NULL);
		if (error)
			goto done;
		if (path == NULL)
			path = "/";
		error = got_repo_map_path(&in_repo_path, repo, path);
		if (error != NULL)
			goto done;
	}

	if (commit_id_str == NULL) {
		struct got_reference *head_ref;
		if (worktree)
			refname = got_worktree_get_head_ref_name(worktree);
		else
			refname = GOT_REF_HEAD;
		error = got_ref_open(&head_ref, repo, refname, 0);
		if (error != NULL)
			goto done;
		error = got_ref_resolve(&commit_id, repo, head_ref);
		got_ref_close(head_ref);
		if (error != NULL)
			goto done;
	} else {
		error = got_repo_match_object_id(&commit_id, NULL,
		    commit_id_str, GOT_OBJ_TYPE_COMMIT, 1, repo);
		if (error)
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
	fprintf(stderr, "usage: %s status [-s status-codes ] [path ...]\n",
	    getprogname());
	exit(1);
}

static const struct got_error *
print_status(void *arg, unsigned char status, unsigned char staged_status,
    const char *path, struct got_object_id *blob_id,
    struct got_object_id *staged_blob_id, struct got_object_id *commit_id,
    int dirfd, const char *de_name)
{
	if (status == staged_status && (status == GOT_STATUS_DELETE))
		status = GOT_STATUS_NO_CHANGE;
	if (arg) {
		char *status_codes = arg;
		size_t ncodes = strlen(status_codes);
		int i;
		for (i = 0; i < ncodes ; i++) {
			if (status == status_codes[i] ||
			    staged_status == status_codes[i])
				break;
		}
		if (i == ncodes)
			return NULL;
	}
	printf("%c%c %s\n", status, staged_status, path);
	return NULL;
}

static const struct got_error *
cmd_status(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *cwd = NULL, *status_codes = NULL;;
	struct got_pathlist_head paths;
	struct got_pathlist_entry *pe;
	int ch, i;

	TAILQ_INIT(&paths);

	while ((ch = getopt(argc, argv, "s:")) != -1) {
		switch (ch) {
		case 's':
			for (i = 0; i < strlen(optarg); i++) {
				switch (optarg[i]) {
				case GOT_STATUS_MODIFY:
				case GOT_STATUS_ADD:
				case GOT_STATUS_DELETE:
				case GOT_STATUS_CONFLICT:
				case GOT_STATUS_MISSING:
				case GOT_STATUS_OBSTRUCTED:
				case GOT_STATUS_UNVERSIONED:
				case GOT_STATUS_MODE_CHANGE:
				case GOT_STATUS_NONEXISTENT:
					break;
				default:
					errx(1, "invalid status code '%c'",
					    optarg[i]);
				}
			}
			status_codes = optarg;
			break;
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
	if (error) {
		if (error->code == GOT_ERR_NOT_WORKTREE)
			error = wrap_not_worktree_error(error, "status", cwd);
		goto done;
	}

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree),
	    NULL);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 1,
	    got_worktree_get_root_path(worktree));
	if (error)
		goto done;

	error = get_worktree_paths_from_argv(&paths, argc, argv, worktree);
	if (error)
		goto done;

	error = got_worktree_status(worktree, &paths, repo, print_status,
	    status_codes, check_cancelled, NULL);
done:
	TAILQ_FOREACH(pe, &paths, entry)
		free((char *)pe->path);
	got_pathlist_free(&paths);
	free(cwd);
	return error;
}

__dead static void
usage_ref(void)
{
	fprintf(stderr,
	    "usage: %s ref [-r repository] [-l] [-c object] [-s reference] "
	        "[-d] [name]\n",
	    getprogname());
	exit(1);
}

static const struct got_error *
list_refs(struct got_repository *repo, const char *refname)
{
	static const struct got_error *err = NULL;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;

	SIMPLEQ_INIT(&refs);
	err = got_ref_list(&refs, repo, refname, got_ref_cmp_by_name, NULL);
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

	/*
	 * Don't let the user create a reference name with a leading '-'.
	 * While technically a valid reference name, this case is usually
	 * an unintended typo.
	 */
	if (refname[0] == '-')
		return got_error_path(refname, GOT_ERR_REF_NAME_MINUS);

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
add_symref(struct got_repository *repo, const char *refname, const char *target)
{
	const struct got_error *err = NULL;
	struct got_reference *ref = NULL;
	struct got_reference *target_ref = NULL;

	/*
	 * Don't let the user create a reference name with a leading '-'.
	 * While technically a valid reference name, this case is usually
	 * an unintended typo.
	 */
	if (refname[0] == '-')
		return got_error_path(refname, GOT_ERR_REF_NAME_MINUS);

	err = got_ref_open(&target_ref, repo, target, 0);
	if (err)
		return err;

	err = got_ref_alloc_symref(&ref, refname, target_ref);
	if (err)
		goto done;

	err = got_ref_write(ref, repo);
done:
	if (target_ref)
		got_ref_close(target_ref);
	if (ref)
		got_ref_close(ref);
	return err;
}

static const struct got_error *
cmd_ref(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *cwd = NULL, *repo_path = NULL;
	int ch, do_list = 0, do_delete = 0;
	const char *obj_arg = NULL, *symref_target= NULL;
	char *refname = NULL;

	while ((ch = getopt(argc, argv, "c:dr:ls:")) != -1) {
		switch (ch) {
		case 'c':
			obj_arg = optarg;
			break;
		case 'd':
			do_delete = 1;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				return got_error_from_errno2("realpath",
				    optarg);
			got_path_strip_trailing_slashes(repo_path);
			break;
		case 'l':
			do_list = 1;
			break;
		case 's':
			symref_target = optarg;
			break;
		default:
			usage_ref();
			/* NOTREACHED */
		}
	}

	if (obj_arg && do_list)
		option_conflict('c', 'l');
	if (obj_arg && do_delete)
		option_conflict('c', 'd');
	if (obj_arg && symref_target)
		option_conflict('c', 's');
	if (symref_target && do_delete)
		option_conflict('s', 'd');
	if (symref_target && do_list)
		option_conflict('s', 'l');
	if (do_delete && do_list)
		option_conflict('d', 'l');

	argc -= optind;
	argv += optind;

	if (do_list) {
		if (argc != 0 && argc != 1)
			usage_ref();
		if (argc == 1) {
			refname = strdup(argv[0]);
			if (refname == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		}
	} else {
		if (argc != 1)
			usage_ref();
		refname = strdup(argv[0]);
		if (refname == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
	}

	if (refname)
		got_path_strip_trailing_slashes(refname);

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

	error = got_repo_open(&repo, repo_path, NULL);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), do_list,
	    worktree ? got_worktree_get_root_path(worktree) : NULL);
	if (error)
		goto done;

	if (do_list)
		error = list_refs(repo, refname);
	else if (do_delete)
		error = delete_ref(repo, refname);
	else if (symref_target)
		error = add_symref(repo, refname, symref_target);
	else {
		if (obj_arg == NULL)
			usage_ref();
		error = add_ref(repo, refname, obj_arg);
	}
done:
	free(refname);
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
	    "usage: %s branch [-c commit] [-d] [-r repository] [-l] [-n] "
	        "[name]\n", getprogname());
	exit(1);
}

static const struct got_error *
list_branch(struct got_repository *repo, struct got_worktree *worktree,
    struct got_reference *ref)
{
	const struct got_error *err = NULL;
	const char *refname, *marker = "  ";
	char *refstr;

	refname = got_ref_get_name(ref);
	if (worktree && strcmp(refname,
	    got_worktree_get_head_ref_name(worktree)) == 0) {
		struct got_object_id *id = NULL;

		err = got_ref_resolve(&id, repo, ref);
		if (err)
			return err;
		if (got_object_id_cmp(id,
		    got_worktree_get_base_commit_id(worktree)) == 0)
			marker = "* ";
		else
			marker = "~ ";
		free(id);
	}

	if (strncmp(refname, "refs/heads/", 11) == 0)
		refname += 11;
	if (strncmp(refname, "refs/got/worktree/", 18) == 0)
		refname += 18;

	refstr = got_ref_to_str(ref);
	if (refstr == NULL)
		return got_error_from_errno("got_ref_to_str");

	printf("%s%s: %s\n", marker, refname, refstr);
	free(refstr);
	return NULL;
}

static const struct got_error *
show_current_branch(struct got_repository *repo, struct got_worktree *worktree)
{
	const char *refname;

	if (worktree == NULL)
		return got_error(GOT_ERR_NOT_WORKTREE);

	refname = got_worktree_get_head_ref_name(worktree);

	if (strncmp(refname, "refs/heads/", 11) == 0)
		refname += 11;
	if (strncmp(refname, "refs/got/worktree/", 18) == 0)
		refname += 18;

	printf("%s\n", refname);

	return NULL;
}

static const struct got_error *
list_branches(struct got_repository *repo, struct got_worktree *worktree)
{
	static const struct got_error *err = NULL;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;
	struct got_reference *temp_ref = NULL;
	int rebase_in_progress, histedit_in_progress;

	SIMPLEQ_INIT(&refs);

	if (worktree) {
		err = got_worktree_rebase_in_progress(&rebase_in_progress,
		    worktree);
		if (err)
			return err;

		err = got_worktree_histedit_in_progress(&histedit_in_progress,
		    worktree);
		if (err)
			return err;

		if (rebase_in_progress || histedit_in_progress) {
			err = got_ref_open(&temp_ref, repo,
			    got_worktree_get_head_ref_name(worktree), 0);
			if (err)
				return err;
			list_branch(repo, worktree, temp_ref);
			got_ref_close(temp_ref);
		}
	}

	err = got_ref_list(&refs, repo, "refs/heads",
	    got_ref_cmp_by_name, NULL);
	if (err)
		return err;

	SIMPLEQ_FOREACH(re, &refs, entry)
		list_branch(repo, worktree, re->ref);

	got_ref_list_free(&refs);
	return NULL;
}

static const struct got_error *
delete_branch(struct got_repository *repo, struct got_worktree *worktree,
    const char *branch_name)
{
	const struct got_error *err = NULL;
	struct got_reference *ref = NULL;
	char *refname;

	if (asprintf(&refname, "refs/heads/%s", branch_name) == -1)
		return got_error_from_errno("asprintf");

	err = got_ref_open(&ref, repo, refname, 0);
	if (err)
		goto done;

	if (worktree &&
	    strcmp(got_worktree_get_head_ref_name(worktree),
	    got_ref_get_name(ref)) == 0) {
		err = got_error_msg(GOT_ERR_SAME_BRANCH,
		    "will not delete this work tree's current branch");
		goto done;
	}

	err = got_ref_delete(ref, repo);
done:
	if (ref)
		got_ref_close(ref);
	free(refname);
	return err;
}

static const struct got_error *
add_branch(struct got_repository *repo, const char *branch_name,
    struct got_object_id *base_commit_id)
{
	const struct got_error *err = NULL;
	struct got_reference *ref = NULL;
	char *base_refname = NULL, *refname = NULL;

	/*
	 * Don't let the user create a branch name with a leading '-'.
	 * While technically a valid reference name, this case is usually
	 * an unintended typo.
	 */
	if (branch_name[0] == '-')
		return got_error_path(branch_name, GOT_ERR_REF_NAME_MINUS);

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

	err = got_ref_alloc(&ref, refname, base_commit_id);
	if (err)
		goto done;

	err = got_ref_write(ref, repo);
done:
	if (ref)
		got_ref_close(ref);
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
	int ch, do_list = 0, do_show = 0, do_update = 1;
	const char *delref = NULL, *commit_id_arg = NULL;
	struct got_reference *ref = NULL;
	struct got_pathlist_head paths;
	struct got_pathlist_entry *pe;
	struct got_object_id *commit_id = NULL;
	char *commit_id_str = NULL;

	TAILQ_INIT(&paths);

	while ((ch = getopt(argc, argv, "c:d:r:ln")) != -1) {
		switch (ch) {
		case 'c':
			commit_id_arg = optarg;
			break;
		case 'd':
			delref = optarg;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				return got_error_from_errno2("realpath",
				    optarg);
			got_path_strip_trailing_slashes(repo_path);
			break;
		case 'l':
			do_list = 1;
			break;
		case 'n':
			do_update = 0;
			break;
		default:
			usage_branch();
			/* NOTREACHED */
		}
	}

	if (do_list && delref)
		option_conflict('l', 'd');

	argc -= optind;
	argv += optind;

	if (!do_list && !delref && argc == 0)
		do_show = 1;

	if ((do_list || delref || do_show) && commit_id_arg != NULL)
		errx(1, "-c option can only be used when creating a branch");

	if (do_list || delref) {
		if (argc > 0)
			usage_branch();
	} else if (!do_show && argc != 1)
		usage_branch();

#ifndef PROFILE
	if (do_list || do_show) {
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

	error = got_repo_open(&repo, repo_path, NULL);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), do_list,
	    worktree ? got_worktree_get_root_path(worktree) : NULL);
	if (error)
		goto done;

	if (do_show)
		error = show_current_branch(repo, worktree);
	else if (do_list)
		error = list_branches(repo, worktree);
	else if (delref)
		error = delete_branch(repo, worktree, delref);
	else {
		if (commit_id_arg == NULL)
			commit_id_arg = worktree ?
			    got_worktree_get_head_ref_name(worktree) :
			    GOT_REF_HEAD;
		error = got_repo_match_object_id(&commit_id, NULL,
		    commit_id_arg, GOT_OBJ_TYPE_COMMIT, 1, repo);
		if (error)
			goto done;
		error = add_branch(repo, argv[0], commit_id);
		if (error)
			goto done;
		if (worktree && do_update) {
			struct got_update_progress_arg upa;
			char *branch_refname = NULL;

			error = got_object_id_str(&commit_id_str, commit_id);
			if (error)
				goto done;
			error = get_worktree_paths_from_argv(&paths, 0, NULL,
			    worktree);
			if (error)
				goto done;
			if (asprintf(&branch_refname, "refs/heads/%s", argv[0])
			    == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}
			error = got_ref_open(&ref, repo, branch_refname, 0);
			free(branch_refname);
			if (error)
				goto done;
			error = switch_head_ref(ref, commit_id, worktree,
			    repo);
			if (error)
				goto done;
			error = got_worktree_set_base_commit_id(worktree, repo,
			    commit_id);
			if (error)
				goto done;
			memset(&upa, 0, sizeof(upa));
			error = got_worktree_checkout_files(worktree, &paths,
			    repo, update_progress, &upa, check_cancelled,
			    NULL);
			if (error)
				goto done;
			if (upa.did_something)
				printf("Updated to commit %s\n", commit_id_str);
			print_update_progress_stats(&upa);
		}
	}
done:
	if (ref)
		got_ref_close(ref);
	if (repo)
		got_repo_close(repo);
	if (worktree)
		got_worktree_close(worktree);
	free(cwd);
	free(repo_path);
	free(commit_id);
	free(commit_id_str);
	TAILQ_FOREACH(pe, &paths, entry)
		free((char *)pe->path);
	got_pathlist_free(&paths);
	return error;
}


__dead static void
usage_tag(void)
{
	fprintf(stderr,
	    "usage: %s tag [-c commit] [-r repository] [-l] "
	        "[-m message] name\n", getprogname());
	exit(1);
}

#if 0
static const struct got_error *
sort_tags(struct got_reflist_head *sorted, struct got_reflist_head *tags)
{
	const struct got_error *err = NULL;
	struct got_reflist_entry *re, *se, *new;
	struct got_object_id *re_id, *se_id;
	struct got_tag_object *re_tag, *se_tag;
	time_t re_time, se_time;

	SIMPLEQ_FOREACH(re, tags, entry) {
		se = SIMPLEQ_FIRST(sorted);
		if (se == NULL) {
			err = got_reflist_entry_dup(&new, re);
			if (err)
				return err;
			SIMPLEQ_INSERT_HEAD(sorted, new, entry);
			continue;
		} else {
			err = got_ref_resolve(&re_id, repo, re->ref);
			if (err)
				break;
			err = got_object_open_as_tag(&re_tag, repo, re_id);
			free(re_id);
			if (err)
				break;
			re_time = got_object_tag_get_tagger_time(re_tag);
			got_object_tag_close(re_tag);
		}

		while (se) {
			err = got_ref_resolve(&se_id, repo, re->ref);
			if (err)
				break;
			err = got_object_open_as_tag(&se_tag, repo, se_id);
			free(se_id);
			if (err)
				break;
			se_time = got_object_tag_get_tagger_time(se_tag);
			got_object_tag_close(se_tag);

			if (se_time > re_time) {
				err = got_reflist_entry_dup(&new, re);
				if (err)
					return err;
				SIMPLEQ_INSERT_AFTER(sorted, se, new, entry);
				break;
			}
			se = SIMPLEQ_NEXT(se, entry);
			continue;
		}
	}
done:
	return err;
}
#endif

static const struct got_error *
list_tags(struct got_repository *repo, struct got_worktree *worktree)
{
	static const struct got_error *err = NULL;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;

	SIMPLEQ_INIT(&refs);

	err = got_ref_list(&refs, repo, "refs/tags", got_ref_cmp_tags, repo);
	if (err)
		return err;

	SIMPLEQ_FOREACH(re, &refs, entry) {
		const char *refname;
		char *refstr, *tagmsg0, *tagmsg, *line, *id_str, *datestr;
		char datebuf[26];
		const char *tagger;
		time_t tagger_time;
		struct got_object_id *id;
		struct got_tag_object *tag;
		struct got_commit_object *commit = NULL;

		refname = got_ref_get_name(re->ref);
		if (strncmp(refname, "refs/tags/", 10) != 0)
			continue;
		refname += 10;
		refstr = got_ref_to_str(re->ref);
		if (refstr == NULL) {
			err = got_error_from_errno("got_ref_to_str");
			break;
		}
		printf("%stag %s %s\n", GOT_COMMIT_SEP_STR, refname, refstr);
		free(refstr);

		err = got_ref_resolve(&id, repo, re->ref);
		if (err)
			break;
		err = got_object_open_as_tag(&tag, repo, id);
		if (err) {
			if (err->code != GOT_ERR_OBJ_TYPE) {
				free(id);
				break;
			}
			/* "lightweight" tag */
			err = got_object_open_as_commit(&commit, repo, id);
			if (err) {
				free(id);
				break;
			}
			tagger = got_object_commit_get_committer(commit);
			tagger_time =
			    got_object_commit_get_committer_time(commit);
			err = got_object_id_str(&id_str, id);
			free(id);
			if (err)
				break;
		} else {
			free(id);
			tagger = got_object_tag_get_tagger(tag);
			tagger_time = got_object_tag_get_tagger_time(tag);
			err = got_object_id_str(&id_str,
			    got_object_tag_get_object_id(tag));
			if (err)
				break;
		}
		printf("from: %s\n", tagger);
		datestr = get_datestr(&tagger_time, datebuf);
		if (datestr)
			printf("date: %s UTC\n", datestr);
		if (commit)
			printf("object: %s %s\n", GOT_OBJ_LABEL_COMMIT, id_str);
		else {
			switch (got_object_tag_get_object_type(tag)) {
			case GOT_OBJ_TYPE_BLOB:
				printf("object: %s %s\n", GOT_OBJ_LABEL_BLOB,
				    id_str);
				break;
			case GOT_OBJ_TYPE_TREE:
				printf("object: %s %s\n", GOT_OBJ_LABEL_TREE,
				    id_str);
				break;
			case GOT_OBJ_TYPE_COMMIT:
				printf("object: %s %s\n", GOT_OBJ_LABEL_COMMIT,
				    id_str);
				break;
			case GOT_OBJ_TYPE_TAG:
				printf("object: %s %s\n", GOT_OBJ_LABEL_TAG,
				    id_str);
				break;
			default:
				break;
			}
		}
		free(id_str);
		if (commit) {
			err = got_object_commit_get_logmsg(&tagmsg0, commit);
			if (err)
				break;
			got_object_commit_close(commit);
		} else {
			tagmsg0 = strdup(got_object_tag_get_message(tag));
			got_object_tag_close(tag);
			if (tagmsg0 == NULL) {
				err = got_error_from_errno("strdup");
				break;
			}
		}

		tagmsg = tagmsg0;
		do {
			line = strsep(&tagmsg, "\n");
			if (line)
				printf(" %s\n", line);
		} while (line);
		free(tagmsg0);
	}

	got_ref_list_free(&refs);
	return NULL;
}

static const struct got_error *
get_tag_message(char **tagmsg, char **tagmsg_path, const char *commit_id_str,
    const char *tag_name, const char *repo_path)
{
	const struct got_error *err = NULL;
	char *template = NULL, *initial_content = NULL;
	char *editor = NULL;
	int initial_content_len;
	int fd = -1;

	if (asprintf(&template, GOT_TMPDIR_STR "/got-tagmsg") == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	initial_content_len = asprintf(&initial_content,
	    "\n# tagging commit %s as %s\n",
	    commit_id_str, tag_name);
	if (initial_content_len == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	err = got_opentemp_named_fd(tagmsg_path, &fd, template);
	if (err)
		goto done;

	if (write(fd, initial_content, initial_content_len) == -1) {
		err = got_error_from_errno2("write", *tagmsg_path);
		goto done;
	}

	err = get_editor(&editor);
	if (err)
		goto done;
	err = edit_logmsg(tagmsg, editor, *tagmsg_path, initial_content,
	    initial_content_len, 1);
done:
	free(initial_content);
	free(template);
	free(editor);

	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno2("close", *tagmsg_path);

	/* Editor is done; we can now apply unveil(2) */
	if (err == NULL)
		err = apply_unveil(repo_path, 0, NULL);
	if (err) {
		free(*tagmsg);
		*tagmsg = NULL;
	}
	return err;
}

static const struct got_error *
add_tag(struct got_repository *repo, struct got_worktree *worktree,
    const char *tag_name, const char *commit_arg, const char *tagmsg_arg)
{
	const struct got_error *err = NULL;
	struct got_object_id *commit_id = NULL, *tag_id = NULL;
	char *label = NULL, *commit_id_str = NULL;
	struct got_reference *ref = NULL;
	char *refname = NULL, *tagmsg = NULL, *tagger = NULL;
	char *tagmsg_path = NULL, *tag_id_str = NULL;
	int preserve_tagmsg = 0;

	/*
	 * Don't let the user create a tag name with a leading '-'.
	 * While technically a valid reference name, this case is usually
	 * an unintended typo.
	 */
	if (tag_name[0] == '-')
		return got_error_path(tag_name, GOT_ERR_REF_NAME_MINUS);

	err = get_author(&tagger, repo, worktree);
	if (err)
		return err;

	err = got_repo_match_object_id(&commit_id, &label, commit_arg,
	    GOT_OBJ_TYPE_COMMIT, 1, repo);
	if (err)
		goto done;

	err = got_object_id_str(&commit_id_str, commit_id);
	if (err)
		goto done;

	if (strncmp("refs/tags/", tag_name, 10) == 0) {
		refname = strdup(tag_name);
		if (refname == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
		tag_name += 10;
	} else if (asprintf(&refname, "refs/tags/%s", tag_name) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	err = got_ref_open(&ref, repo, refname, 0);
	if (err == NULL) {
		err = got_error(GOT_ERR_TAG_EXISTS);
		goto done;
	} else if (err->code != GOT_ERR_NOT_REF)
		goto done;

	if (tagmsg_arg == NULL) {
		err = get_tag_message(&tagmsg, &tagmsg_path, commit_id_str,
		    tag_name, got_repo_get_path(repo));
		if (err) {
			if (err->code != GOT_ERR_COMMIT_MSG_EMPTY &&
			    tagmsg_path != NULL)
				preserve_tagmsg = 1;
			goto done;
		}
	}

	err = got_object_tag_create(&tag_id, tag_name, commit_id,
	    tagger, time(NULL), tagmsg ? tagmsg : tagmsg_arg, repo);
	if (err) {
		if (tagmsg_path)
			preserve_tagmsg = 1;
		goto done;
	}

	err = got_ref_alloc(&ref, refname, tag_id);
	if (err) {
		if (tagmsg_path)
			preserve_tagmsg = 1;
		goto done;
	}

	err = got_ref_write(ref, repo);
	if (err) {
		if (tagmsg_path)
			preserve_tagmsg = 1;
		goto done;
	}

	err = got_object_id_str(&tag_id_str, tag_id);
	if (err) {
		if (tagmsg_path)
			preserve_tagmsg = 1;
		goto done;
	}
	printf("Created tag %s\n", tag_id_str);
done:
	if (preserve_tagmsg) {
		fprintf(stderr, "%s: tag message preserved in %s\n",
		    getprogname(), tagmsg_path);
	} else if (tagmsg_path && unlink(tagmsg_path) == -1 && err == NULL)
		err = got_error_from_errno2("unlink", tagmsg_path);
	free(tag_id_str);
	if (ref)
		got_ref_close(ref);
	free(commit_id);
	free(commit_id_str);
	free(refname);
	free(tagmsg);
	free(tagmsg_path);
	free(tagger);
	return err;
}

static const struct got_error *
cmd_tag(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *cwd = NULL, *repo_path = NULL, *commit_id_str = NULL;
	char *gitconfig_path = NULL;
	const char *tag_name, *commit_id_arg = NULL, *tagmsg = NULL;
	int ch, do_list = 0;

	while ((ch = getopt(argc, argv, "c:m:r:l")) != -1) {
		switch (ch) {
		case 'c':
			commit_id_arg = optarg;
			break;
		case 'm':
			tagmsg = optarg;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				return got_error_from_errno2("realpath",
				    optarg);
			got_path_strip_trailing_slashes(repo_path);
			break;
		case 'l':
			do_list = 1;
			break;
		default:
			usage_tag();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (do_list) {
		if (commit_id_arg != NULL)
			errx(1,
			    "-c option can only be used when creating a tag");
		if (tagmsg)
			option_conflict('l', 'm');
		if (argc > 0)
			usage_tag();
	} else if (argc != 1)
		usage_tag();

	tag_name = argv[0];

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

	if (do_list) {
		error = got_repo_open(&repo, repo_path, NULL);
		if (error != NULL)
			goto done;
		error = apply_unveil(got_repo_get_path(repo), 1, NULL);
		if (error)
			goto done;
		error = list_tags(repo, worktree);
	} else {
		error = get_gitconfig_path(&gitconfig_path);
		if (error)
			goto done;
		error = got_repo_open(&repo, repo_path, gitconfig_path);
		if (error != NULL)
			goto done;

		if (tagmsg) {
			error = apply_unveil(got_repo_get_path(repo), 0, NULL);
			if (error)
				goto done;
		}

		if (commit_id_arg == NULL) {
			struct got_reference *head_ref;
			struct got_object_id *commit_id;
			error = got_ref_open(&head_ref, repo,
			    worktree ? got_worktree_get_head_ref_name(worktree)
			    : GOT_REF_HEAD, 0);
			if (error)
				goto done;
			error = got_ref_resolve(&commit_id, repo, head_ref);
			got_ref_close(head_ref);
			if (error)
				goto done;
			error = got_object_id_str(&commit_id_str, commit_id);
			free(commit_id);
			if (error)
				goto done;
		}

		error = add_tag(repo, worktree, tag_name,
		    commit_id_str ? commit_id_str : commit_id_arg, tagmsg);
	}
done:
	if (repo)
		got_repo_close(repo);
	if (worktree)
		got_worktree_close(worktree);
	free(cwd);
	free(repo_path);
	free(gitconfig_path);
	free(commit_id_str);
	return error;
}

__dead static void
usage_add(void)
{
	fprintf(stderr, "usage: %s add [-R] [-I] path ...\n",
	    getprogname());
	exit(1);
}

static const struct got_error *
add_progress(void *arg, unsigned char status, const char *path)
{
	while (path[0] == '/')
		path++;
	printf("%c  %s\n", status, path);
	return NULL;
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
	int ch, can_recurse = 0, no_ignores = 0;

	TAILQ_INIT(&paths);

	while ((ch = getopt(argc, argv, "IR")) != -1) {
		switch (ch) {
		case 'I':
			no_ignores = 1;
			break;
		case 'R':
			can_recurse = 1;
			break;
		default:
			usage_add();
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
	if (argc < 1)
		usage_add();

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_worktree_open(&worktree, cwd);
	if (error) {
		if (error->code == GOT_ERR_NOT_WORKTREE)
			error = wrap_not_worktree_error(error, "add", cwd);
		goto done;
	}

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree),
	    NULL);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 1,
	    got_worktree_get_root_path(worktree));
	if (error)
		goto done;

	error = get_worktree_paths_from_argv(&paths, argc, argv, worktree);
	if (error)
		goto done;

	if (!can_recurse && no_ignores) {
		error = got_error_msg(GOT_ERR_BAD_PATH,
		    "disregarding ignores requires -R option");
		goto done;

	}

	if (!can_recurse) {
		char *ondisk_path;
		struct stat sb;
		TAILQ_FOREACH(pe, &paths, entry) {
			if (asprintf(&ondisk_path, "%s/%s",
			    got_worktree_get_root_path(worktree),
			    pe->path) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}
			if (lstat(ondisk_path, &sb) == -1) {
				if (errno == ENOENT) {
					free(ondisk_path);
					continue;
				}
				error = got_error_from_errno2("lstat",
				    ondisk_path);
				free(ondisk_path);
				goto done;
			}
			free(ondisk_path);
			if (S_ISDIR(sb.st_mode)) {
				error = got_error_msg(GOT_ERR_BAD_PATH,
				    "adding directories requires -R option");
				goto done;
			}
		}
	}

	error = got_worktree_schedule_add(worktree, &paths, add_progress,
	    NULL, repo, no_ignores);
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
	fprintf(stderr, "usage: %s remove [-f] [-k] [-R] [-s status-codes] "
	    "path ...\n", getprogname());
	exit(1);
}

static const struct got_error *
print_remove_status(void *arg, unsigned char status,
    unsigned char staged_status, const char *path)
{
	while (path[0] == '/')
		path++;
	if (status == GOT_STATUS_NONEXISTENT)
		return NULL;
	if (status == staged_status && (status == GOT_STATUS_DELETE))
		status = GOT_STATUS_NO_CHANGE;
	printf("%c%c %s\n", status, staged_status, path);
	return NULL;
}

static const struct got_error *
cmd_remove(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_worktree *worktree = NULL;
	struct got_repository *repo = NULL;
	const char *status_codes = NULL;
	char *cwd = NULL;
	struct got_pathlist_head paths;
	struct got_pathlist_entry *pe;
	int ch, delete_local_mods = 0, can_recurse = 0, keep_on_disk = 0, i;

	TAILQ_INIT(&paths);

	while ((ch = getopt(argc, argv, "fkRs:")) != -1) {
		switch (ch) {
		case 'f':
			delete_local_mods = 1;
			break;
		case 'k':
			keep_on_disk = 1;
			break;
		case 'R':
			can_recurse = 1;
			break;
		case 's':
			for (i = 0; i < strlen(optarg); i++) {
				switch (optarg[i]) {
				case GOT_STATUS_MODIFY:
					delete_local_mods = 1;
					break;
				case GOT_STATUS_MISSING:
					break;
				default:
					errx(1, "invalid status code '%c'",
					    optarg[i]);
				}
			}
			status_codes = optarg;
			break;
		default:
			usage_remove();
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
	if (argc < 1)
		usage_remove();

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}
	error = got_worktree_open(&worktree, cwd);
	if (error) {
		if (error->code == GOT_ERR_NOT_WORKTREE)
			error = wrap_not_worktree_error(error, "remove", cwd);
		goto done;
	}

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree),
	    NULL);
	if (error)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 1,
	    got_worktree_get_root_path(worktree));
	if (error)
		goto done;

	error = get_worktree_paths_from_argv(&paths, argc, argv, worktree);
	if (error)
		goto done;

	if (!can_recurse) {
		char *ondisk_path;
		struct stat sb;
		TAILQ_FOREACH(pe, &paths, entry) {
			if (asprintf(&ondisk_path, "%s/%s",
			    got_worktree_get_root_path(worktree),
			    pe->path) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}
			if (lstat(ondisk_path, &sb) == -1) {
				if (errno == ENOENT) {
					free(ondisk_path);
					continue;
				}
				error = got_error_from_errno2("lstat",
				    ondisk_path);
				free(ondisk_path);
				goto done;
			}
			free(ondisk_path);
			if (S_ISDIR(sb.st_mode)) {
				error = got_error_msg(GOT_ERR_BAD_PATH,
				    "removing directories requires -R option");
				goto done;
			}
		}
	}

	error = got_worktree_schedule_delete(worktree, &paths,
	    delete_local_mods, status_codes, print_remove_status, NULL,
	    repo, keep_on_disk);
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
	fprintf(stderr, "usage: %s revert [-p] [-F response-script] [-R] "
	    "path ...\n", getprogname());
	exit(1);
}

static const struct got_error *
revert_progress(void *arg, unsigned char status, const char *path)
{
	if (status == GOT_STATUS_UNVERSIONED)
		return NULL;

	while (path[0] == '/')
		path++;
	printf("%c  %s\n", status, path);
	return NULL;
}

struct choose_patch_arg {
	FILE *patch_script_file;
	const char *action;
};

static const struct got_error *
show_change(unsigned char status, const char *path, FILE *patch_file, int n,
    int nchanges, const char *action)
{
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;

	switch (status) {
	case GOT_STATUS_ADD:
		printf("A  %s\n%s this addition? [y/n] ", path, action);
		break;
	case GOT_STATUS_DELETE:
		printf("D  %s\n%s this deletion? [y/n] ", path, action);
		break;
	case GOT_STATUS_MODIFY:
		if (fseek(patch_file, 0L, SEEK_SET) == -1)
			return got_error_from_errno("fseek");
		printf(GOT_COMMIT_SEP_STR);
		while ((linelen = getline(&line, &linesize, patch_file)) != -1)
			printf("%s", line);
		if (ferror(patch_file))
			return got_error_from_errno("getline");
		printf(GOT_COMMIT_SEP_STR);
		printf("M  %s (change %d of %d)\n%s this change? [y/n/q] ",
		    path, n, nchanges, action);
		break;
	default:
		return got_error_path(path, GOT_ERR_FILE_STATUS);
	}

	return NULL;
}

static const struct got_error *
choose_patch(int *choice, void *arg, unsigned char status, const char *path,
    FILE *patch_file, int n, int nchanges)
{
	const struct got_error *err = NULL;
	char *line = NULL;
	size_t linesize = 0;
	ssize_t linelen;
	int resp = ' ';
	struct choose_patch_arg *a = arg;

	*choice = GOT_PATCH_CHOICE_NONE;

	if (a->patch_script_file) {
		char *nl;
		err = show_change(status, path, patch_file, n, nchanges,
		    a->action);
		if (err)
			return err;
		linelen = getline(&line, &linesize, a->patch_script_file);
		if (linelen == -1) {
			if (ferror(a->patch_script_file))
				return got_error_from_errno("getline");
			return NULL;
		}
		nl = strchr(line, '\n');
		if (nl)
			*nl = '\0';
		if (strcmp(line, "y") == 0) {
			*choice = GOT_PATCH_CHOICE_YES;
			printf("y\n");
		} else if (strcmp(line, "n") == 0) {
			*choice = GOT_PATCH_CHOICE_NO;
			printf("n\n");
		} else if (strcmp(line, "q") == 0 &&
		    status == GOT_STATUS_MODIFY) {
			*choice = GOT_PATCH_CHOICE_QUIT;
			printf("q\n");
		} else
			printf("invalid response '%s'\n", line);
		free(line);
		return NULL;
	}

	while (resp != 'y' && resp != 'n' && resp != 'q') {
		err = show_change(status, path, patch_file, n, nchanges,
		    a->action);
		if (err)
			return err;
		resp = getchar();
		if (resp == '\n')
			resp = getchar();
		if (status == GOT_STATUS_MODIFY) {
			if (resp != 'y' && resp != 'n' && resp != 'q') {
				printf("invalid response '%c'\n", resp);
				resp = ' ';
			}
		} else if (resp != 'y' && resp != 'n') {
				printf("invalid response '%c'\n", resp);
				resp = ' ';
		}
	}

	if (resp == 'y')
		*choice = GOT_PATCH_CHOICE_YES;
	else if (resp == 'n')
		*choice = GOT_PATCH_CHOICE_NO;
	else if (resp == 'q' && status == GOT_STATUS_MODIFY)
		*choice = GOT_PATCH_CHOICE_QUIT;

	return NULL;
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
	int ch, can_recurse = 0, pflag = 0;
	FILE *patch_script_file = NULL;
	const char *patch_script_path = NULL;
	struct choose_patch_arg cpa;

	TAILQ_INIT(&paths);

	while ((ch = getopt(argc, argv, "pF:R")) != -1) {
		switch (ch) {
		case 'p':
			pflag = 1;
			break;
		case 'F':
			patch_script_path = optarg;
			break;
		case 'R':
			can_recurse = 1;
			break;
		default:
			usage_revert();
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
	if (argc < 1)
		usage_revert();
	if (patch_script_path && !pflag)
		errx(1, "-F option can only be used together with -p option");

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}
	error = got_worktree_open(&worktree, cwd);
	if (error) {
		if (error->code == GOT_ERR_NOT_WORKTREE)
			error = wrap_not_worktree_error(error, "revert", cwd);
		goto done;
	}

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree),
	    NULL);
	if (error != NULL)
		goto done;

	if (patch_script_path) {
		patch_script_file = fopen(patch_script_path, "r");
		if (patch_script_file == NULL) {
			error = got_error_from_errno2("fopen",
			    patch_script_path);
			goto done;
		}
	}
	error = apply_unveil(got_repo_get_path(repo), 1,
	    got_worktree_get_root_path(worktree));
	if (error)
		goto done;

	error = get_worktree_paths_from_argv(&paths, argc, argv, worktree);
	if (error)
		goto done;

	if (!can_recurse) {
		char *ondisk_path;
		struct stat sb;
		TAILQ_FOREACH(pe, &paths, entry) {
			if (asprintf(&ondisk_path, "%s/%s",
			    got_worktree_get_root_path(worktree),
			    pe->path) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}
			if (lstat(ondisk_path, &sb) == -1) {
				if (errno == ENOENT) {
					free(ondisk_path);
					continue;
				}
				error = got_error_from_errno2("lstat",
				    ondisk_path);
				free(ondisk_path);
				goto done;
			}
			free(ondisk_path);
			if (S_ISDIR(sb.st_mode)) {
				error = got_error_msg(GOT_ERR_BAD_PATH,
				    "reverting directories requires -R option");
				goto done;
			}
		}
	}

	cpa.patch_script_file = patch_script_file;
	cpa.action = "revert";
	error = got_worktree_revert(worktree, &paths, revert_progress, NULL,
	    pflag ? choose_patch : NULL, &cpa, repo);
done:
	if (patch_script_file && fclose(patch_script_file) == EOF &&
	    error == NULL)
		error = got_error_from_errno2("fclose", patch_script_path);
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
	fprintf(stderr, "usage: %s commit [-m msg] [-S] [path ...]\n",
	    getprogname());
	exit(1);
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
	int initial_content_len;
	int fd = -1;
	size_t len;

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

	initial_content_len = asprintf(&initial_content,
	    "\n# changes to be committed on branch %s:\n",
	    a->branch_name);
	if (initial_content_len == -1)
		return got_error_from_errno("asprintf");

	err = got_opentemp_named_fd(&a->logmsg_path, &fd, template);
	if (err)
		goto done;

	if (write(fd, initial_content, initial_content_len) == -1) {
		err = got_error_from_errno2("write", a->logmsg_path);
		goto done;
	}

	TAILQ_FOREACH(pe, commitable_paths, entry) {
		struct got_commitable *ct = pe->data;
		dprintf(fd, "#  %c  %s\n",
		    got_commitable_get_status(ct),
		    got_commitable_get_path(ct));
	}

	err = edit_logmsg(logmsg, a->editor, a->logmsg_path, initial_content,
	    initial_content_len, 1);
done:
	free(initial_content);
	free(template);

	if (fd != -1 && close(fd) == -1 && err == NULL)
		err = got_error_from_errno2("close", a->logmsg_path);

	/* Editor is done; we can now apply unveil(2) */
	if (err == NULL)
		err = apply_unveil(a->repo_path, 0, a->worktree_path);
	if (err) {
		free(*logmsg);
		*logmsg = NULL;
	}
	return err;
}

static const struct got_error *
cmd_commit(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_worktree *worktree = NULL;
	struct got_repository *repo = NULL;
	char *cwd = NULL, *id_str = NULL;
	struct got_object_id *id = NULL;
	const char *logmsg = NULL;
	struct collect_commit_logmsg_arg cl_arg;
	char *gitconfig_path = NULL, *editor = NULL, *author = NULL;
	int ch, rebase_in_progress, histedit_in_progress, preserve_logmsg = 0;
	int allow_bad_symlinks = 0;
	struct got_pathlist_head paths;

	TAILQ_INIT(&paths);
	cl_arg.logmsg_path = NULL;

	while ((ch = getopt(argc, argv, "m:S")) != -1) {
		switch (ch) {
		case 'm':
			logmsg = optarg;
			break;
		case 'S':
			allow_bad_symlinks = 1;
			break;
		default:
			usage_commit();
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
	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}
	error = got_worktree_open(&worktree, cwd);
	if (error) {
		if (error->code == GOT_ERR_NOT_WORKTREE)
			error = wrap_not_worktree_error(error, "commit", cwd);
		goto done;
	}

	error = got_worktree_rebase_in_progress(&rebase_in_progress, worktree);
	if (error)
		goto done;
	if (rebase_in_progress) {
		error = got_error(GOT_ERR_REBASING);
		goto done;
	}

	error = got_worktree_histedit_in_progress(&histedit_in_progress,
	    worktree);
	if (error)
		goto done;

	error = get_gitconfig_path(&gitconfig_path);
	if (error)
		goto done;
	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree),
	    gitconfig_path);
	if (error != NULL)
		goto done;

	error = get_author(&author, repo, worktree);
	if (error)
		return error;

	/*
	 * unveil(2) traverses exec(2); if an editor is used we have
	 * to apply unveil after the log message has been written.
	 */
	if (logmsg == NULL || strlen(logmsg) == 0)
		error = get_editor(&editor);
	else
		error = apply_unveil(got_repo_get_path(repo), 0,
		    got_worktree_get_root_path(worktree));
	if (error)
		goto done;

	error = get_worktree_paths_from_argv(&paths, argc, argv, worktree);
	if (error)
		goto done;

	cl_arg.editor = editor;
	cl_arg.cmdline_log = logmsg;
	cl_arg.worktree_path = got_worktree_get_root_path(worktree);
	cl_arg.branch_name = got_worktree_get_head_ref_name(worktree);
	if (!histedit_in_progress) {
		if (strncmp(cl_arg.branch_name, "refs/heads/", 11) != 0) {
			error = got_error(GOT_ERR_COMMIT_BRANCH);
			goto done;
		}
		cl_arg.branch_name += 11;
	}
	cl_arg.repo_path = got_repo_get_path(repo);
	error = got_worktree_commit(&id, worktree, &paths, author, NULL,
	    allow_bad_symlinks, collect_commit_logmsg, &cl_arg,
	    print_status, NULL, repo);
	if (error) {
		if (error->code != GOT_ERR_COMMIT_MSG_EMPTY &&
		    cl_arg.logmsg_path != NULL)
			preserve_logmsg = 1;
		goto done;
	}

	error = got_object_id_str(&id_str, id);
	if (error)
		goto done;
	printf("Created commit %s\n", id_str);
done:
	if (preserve_logmsg) {
		fprintf(stderr, "%s: log message preserved in %s\n",
		    getprogname(), cl_arg.logmsg_path);
	} else if (cl_arg.logmsg_path && unlink(cl_arg.logmsg_path) == -1 &&
	    error == NULL)
		error = got_error_from_errno2("unlink", cl_arg.logmsg_path);
	free(cl_arg.logmsg_path);
	if (repo)
		got_repo_close(repo);
	if (worktree)
		got_worktree_close(worktree);
	free(cwd);
	free(id_str);
	free(gitconfig_path);
	free(editor);
	free(author);
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
	int ch;
	struct got_update_progress_arg upa;

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			usage_cherrypick();
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
	if (argc != 1)
		usage_cherrypick();

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}
	error = got_worktree_open(&worktree, cwd);
	if (error) {
		if (error->code == GOT_ERR_NOT_WORKTREE)
			error = wrap_not_worktree_error(error, "cherrypick",
			    cwd);
		goto done;
	}

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree),
	    NULL);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 0,
	    got_worktree_get_root_path(worktree));
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

	error = check_same_branch(commit_id, head_ref, NULL, repo);
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
	memset(&upa, 0, sizeof(upa));
	error = got_worktree_merge_files(worktree, pid ? pid->id : NULL,
	    commit_id, repo, update_progress, &upa, check_cancelled,
	    NULL);
	if (error != NULL)
		goto done;

	if (upa.did_something)
		printf("Merged commit %s\n", commit_id_str);
	print_update_progress_stats(&upa);
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
	int ch;
	struct got_update_progress_arg upa;

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			usage_backout();
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
	if (argc != 1)
		usage_backout();

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}
	error = got_worktree_open(&worktree, cwd);
	if (error) {
		if (error->code == GOT_ERR_NOT_WORKTREE)
			error = wrap_not_worktree_error(error, "backout", cwd);
		goto done;
	}

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree),
	    NULL);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 0,
	    got_worktree_get_root_path(worktree));
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

	error = check_same_branch(commit_id, head_ref, NULL, repo);
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

	memset(&upa, 0, sizeof(upa));
	error = got_worktree_merge_files(worktree, commit_id, pid->id, repo,
	    update_progress, &upa, check_cancelled, NULL);
	if (error != NULL)
		goto done;

	if (upa.did_something)
		printf("Backed out commit %s\n", commit_id_str);
	print_update_progress_stats(&upa);
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
	fprintf(stderr, "usage: %s rebase [-a] | [-c] | branch\n",
	    getprogname());
	exit(1);
}

void
trim_logmsg(char *logmsg, int limit)
{
	char *nl;
	size_t len;

	len = strlen(logmsg);
	if (len > limit)
		len = limit;
	logmsg[len] = '\0';
	nl = strchr(logmsg, '\n');
	if (nl)
		*nl = '\0';
}

static const struct got_error *
get_short_logmsg(char **logmsg, int limit, struct got_commit_object *commit)
{
	const struct got_error *err;
	char *logmsg0 = NULL;
	const char *s;

	err = got_object_commit_get_logmsg(&logmsg0, commit);
	if (err)
		return err;

	s = logmsg0;
	while (isspace((unsigned char)s[0]))
		s++;

	*logmsg = strdup(s);
	if (*logmsg == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

	trim_logmsg(*logmsg, limit);
done:
	free(logmsg0);
	return err;
}

static const struct got_error *
show_rebase_merge_conflict(struct got_object_id *id, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_commit_object *commit = NULL;
	char *id_str = NULL, *logmsg = NULL;

	err = got_object_open_as_commit(&commit, repo, id);
	if (err)
		return err;

	err = got_object_id_str(&id_str, id);
	if (err)
		goto done;

	id_str[12] = '\0';

	err = get_short_logmsg(&logmsg, 42, commit);
	if (err)
		goto done;

	printf("%s -> merge conflict: %s\n", id_str, logmsg);
done:
	free(id_str);
	got_object_commit_close(commit);
	free(logmsg);
	return err;
}

static const struct got_error *
show_rebase_progress(struct got_commit_object *commit,
    struct got_object_id *old_id, struct got_object_id *new_id)
{
	const struct got_error *err;
	char *old_id_str = NULL, *new_id_str = NULL, *logmsg = NULL;

	err = got_object_id_str(&old_id_str, old_id);
	if (err)
		goto done;

	if (new_id) {
		err = got_object_id_str(&new_id_str, new_id);
		if (err)
			goto done;
	}

	old_id_str[12] = '\0';
	if (new_id_str)
		new_id_str[12] = '\0';

	err = get_short_logmsg(&logmsg, 42, commit);
	if (err)
		goto done;

	printf("%s -> %s: %s\n", old_id_str,
	    new_id_str ? new_id_str : "no-op change", logmsg);
done:
	free(old_id_str);
	free(new_id_str);
	free(logmsg);
	return err;
}

static const struct got_error *
rebase_complete(struct got_worktree *worktree, struct got_fileindex *fileindex,
    struct got_reference *branch, struct got_reference *new_base_branch,
    struct got_reference *tmp_branch, struct got_repository *repo)
{
	printf("Switching work tree to %s\n", got_ref_get_name(branch));
	return got_worktree_rebase_complete(worktree, fileindex,
	    new_base_branch, tmp_branch, branch, repo);
}

static const struct got_error *
rebase_commit(struct got_pathlist_head *merged_paths,
    struct got_worktree *worktree, struct got_fileindex *fileindex,
    struct got_reference *tmp_branch,
    struct got_object_id *commit_id, struct got_repository *repo)
{
	const struct got_error *error;
	struct got_commit_object *commit;
	struct got_object_id *new_commit_id;

	error = got_object_open_as_commit(&commit, repo, commit_id);
	if (error)
		return error;

	error = got_worktree_rebase_commit(&new_commit_id, merged_paths,
	    worktree, fileindex, tmp_branch, commit, commit_id, repo);
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

struct check_path_prefix_arg {
	const char *path_prefix;
	size_t len;
	int errcode;
};

static const struct got_error *
check_path_prefix_in_diff(void *arg, struct got_blob_object *blob1,
    struct got_blob_object *blob2, struct got_object_id *id1,
    struct got_object_id *id2, const char *path1, const char *path2,
    mode_t mode1, mode_t mode2, struct got_repository *repo)
{
	struct check_path_prefix_arg *a = arg;

	if ((path1 && !got_path_is_child(path1, a->path_prefix, a->len)) ||
	    (path2 && !got_path_is_child(path2, a->path_prefix, a->len)))
		return got_error(a->errcode);

	return NULL;
}

static const struct got_error *
check_path_prefix(struct got_object_id *parent_id,
    struct got_object_id *commit_id, const char *path_prefix,
    int errcode, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_tree_object *tree1 = NULL, *tree2 = NULL;
	struct got_commit_object *commit = NULL, *parent_commit = NULL;
	struct check_path_prefix_arg cpp_arg;

	if (got_path_is_root_dir(path_prefix))
		return NULL;

	err = got_object_open_as_commit(&commit, repo, commit_id);
	if (err)
		goto done;

	err = got_object_open_as_commit(&parent_commit, repo, parent_id);
	if (err)
		goto done;

	err = got_object_open_as_tree(&tree1, repo,
	    got_object_commit_get_tree_id(parent_commit));
	if (err)
		goto done;

	err = got_object_open_as_tree(&tree2, repo,
	    got_object_commit_get_tree_id(commit));
	if (err)
		goto done;

	cpp_arg.path_prefix = path_prefix;
	while (cpp_arg.path_prefix[0] == '/')
		cpp_arg.path_prefix++;
	cpp_arg.len = strlen(cpp_arg.path_prefix);
	cpp_arg.errcode = errcode;
	err = got_diff_tree(tree1, tree2, "", "", repo,
	    check_path_prefix_in_diff, &cpp_arg, 0);
done:
	if (tree1)
		got_object_tree_close(tree1);
	if (tree2)
		got_object_tree_close(tree2);
	if (commit)
		got_object_commit_close(commit);
	if (parent_commit)
		got_object_commit_close(parent_commit);
	return err;
}

static const struct got_error *
collect_commits(struct got_object_id_queue *commits,
    struct got_object_id *initial_commit_id,
    struct got_object_id *iter_start_id, struct got_object_id *iter_stop_id,
    const char *path_prefix, int path_prefix_errcode,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_commit_graph *graph = NULL;
	struct got_object_id *parent_id = NULL;
	struct got_object_qid *qid;
        struct got_object_id *commit_id = initial_commit_id;

	err = got_commit_graph_open(&graph, "/", 1);
	if (err)
		return err;

	err = got_commit_graph_iter_start(graph, iter_start_id, repo,
	    check_cancelled, NULL);
	if (err)
		goto done;
	while (got_object_id_cmp(commit_id, iter_stop_id) != 0) {
		err = got_commit_graph_iter_next(&parent_id, graph, repo,
		    check_cancelled, NULL);
		if (err) {
			if (err->code == GOT_ERR_ITER_COMPLETED) {
				err = got_error_msg(GOT_ERR_ANCESTRY,
				    "ran out of commits to rebase before "
				    "youngest common ancestor commit has "
				    "been reached?!?");
			}
			goto done;
		} else {
			err = check_path_prefix(parent_id, commit_id,
			    path_prefix, path_prefix_errcode, repo);
			if (err)
				goto done;

			err = got_object_qid_alloc(&qid, commit_id);
			if (err)
				goto done;
			SIMPLEQ_INSERT_HEAD(commits, qid, entry);
			commit_id = parent_id;
		}
	}
done:
	got_commit_graph_close(graph);
	return err;
}

static const struct got_error *
cmd_rebase(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_worktree *worktree = NULL;
	struct got_repository *repo = NULL;
	struct got_fileindex *fileindex = NULL;
	char *cwd = NULL;
	struct got_reference *branch = NULL;
	struct got_reference *new_base_branch = NULL, *tmp_branch = NULL;
	struct got_object_id *commit_id = NULL, *parent_id = NULL;
	struct got_object_id *resume_commit_id = NULL;
	struct got_object_id *branch_head_commit_id = NULL, *yca_id = NULL;
	struct got_commit_object *commit = NULL;
	int ch, rebase_in_progress = 0, abort_rebase = 0, continue_rebase = 0;
	int histedit_in_progress = 0;
	unsigned char rebase_status = GOT_STATUS_NO_CHANGE;
	struct got_object_id_queue commits;
	struct got_pathlist_head merged_paths;
	const struct got_object_id_queue *parent_ids;
	struct got_object_qid *qid, *pid;

	SIMPLEQ_INIT(&commits);
	TAILQ_INIT(&merged_paths);

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

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec sendfd "
	    "unveil", NULL) == -1)
		err(1, "pledge");
#endif
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
	if (error) {
		if (error->code == GOT_ERR_NOT_WORKTREE)
			error = wrap_not_worktree_error(error, "rebase", cwd);
		goto done;
	}

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree),
	    NULL);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 0,
	    got_worktree_get_root_path(worktree));
	if (error)
		goto done;

	error = got_worktree_histedit_in_progress(&histedit_in_progress,
	    worktree);
	if (error)
		goto done;
	if (histedit_in_progress) {
		error = got_error(GOT_ERR_HISTEDIT_BUSY);
		goto done;
	}

	error = got_worktree_rebase_in_progress(&rebase_in_progress, worktree);
	if (error)
		goto done;

	if (abort_rebase) {
		struct got_update_progress_arg upa;
		if (!rebase_in_progress) {
			error = got_error(GOT_ERR_NOT_REBASING);
			goto done;
		}
		error = got_worktree_rebase_continue(&resume_commit_id,
		    &new_base_branch, &tmp_branch, &branch, &fileindex,
		    worktree, repo);
		if (error)
			goto done;
		printf("Switching work tree to %s\n",
		    got_ref_get_symref_target(new_base_branch));
		memset(&upa, 0, sizeof(upa));
		error = got_worktree_rebase_abort(worktree, fileindex, repo,
		    new_base_branch, update_progress, &upa);
		if (error)
			goto done;
		printf("Rebase of %s aborted\n", got_ref_get_name(branch));
		print_update_progress_stats(&upa);
		goto done; /* nothing else to do */
	}

	if (continue_rebase) {
		if (!rebase_in_progress) {
			error = got_error(GOT_ERR_NOT_REBASING);
			goto done;
		}
		error = got_worktree_rebase_continue(&resume_commit_id,
		    &new_base_branch, &tmp_branch, &branch, &fileindex,
		    worktree, repo);
		if (error)
			goto done;

		error = rebase_commit(NULL, worktree, fileindex, tmp_branch,
		    resume_commit_id, repo);
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
	}

	error = got_ref_resolve(&branch_head_commit_id, repo, branch);
	if (error)
		goto done;

	if (!continue_rebase) {
		struct got_object_id *base_commit_id;

		base_commit_id = got_worktree_get_base_commit_id(worktree);
		error = got_commit_graph_find_youngest_common_ancestor(&yca_id,
		    base_commit_id, branch_head_commit_id, repo,
		    check_cancelled, NULL);
		if (error)
			goto done;
		if (yca_id == NULL) {
			error = got_error_msg(GOT_ERR_ANCESTRY,
			    "specified branch shares no common ancestry "
			    "with work tree's branch");
			goto done;
		}

		error = check_same_branch(base_commit_id, branch, yca_id, repo);
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
		error = got_worktree_rebase_prepare(&new_base_branch,
		    &tmp_branch, &fileindex, worktree, branch, repo);
		if (error)
			goto done;
	}

	commit_id = branch_head_commit_id;
	error = got_object_open_as_commit(&commit, repo, commit_id);
	if (error)
		goto done;

	parent_ids = got_object_commit_get_parent_ids(commit);
	pid = SIMPLEQ_FIRST(parent_ids);
	if (pid == NULL) {
		if (!continue_rebase) {
			struct got_update_progress_arg upa;
			memset(&upa, 0, sizeof(upa));
			error = got_worktree_rebase_abort(worktree, fileindex,
			    repo, new_base_branch, update_progress, &upa);
			if (error)
				goto done;
			printf("Rebase of %s aborted\n",
			    got_ref_get_name(branch));
			print_update_progress_stats(&upa);

		}
		error = got_error(GOT_ERR_EMPTY_REBASE);
		goto done;
	}
	error = collect_commits(&commits, commit_id, pid->id,
	    yca_id, got_worktree_get_path_prefix(worktree),
	    GOT_ERR_REBASE_PATH, repo);
	got_object_commit_close(commit);
	commit = NULL;
	if (error)
		goto done;

	if (SIMPLEQ_EMPTY(&commits)) {
		if (continue_rebase) {
			error = rebase_complete(worktree, fileindex,
			    branch, new_base_branch, tmp_branch, repo);
			goto done;
		} else {
			/* Fast-forward the reference of the branch. */
			struct got_object_id *new_head_commit_id;
			char *id_str;
			error = got_ref_resolve(&new_head_commit_id, repo,
			    new_base_branch);
			if (error)
				goto done;
			error = got_object_id_str(&id_str, new_head_commit_id);
			printf("Forwarding %s to commit %s\n",
			    got_ref_get_name(branch), id_str);
			free(id_str);
			error = got_ref_change_ref(branch,
			    new_head_commit_id);
			if (error)
				goto done;
		}
	}

	pid = NULL;
	SIMPLEQ_FOREACH(qid, &commits, entry) {
		struct got_update_progress_arg upa;

		commit_id = qid->id;
		parent_id = pid ? pid->id : yca_id;
		pid = qid;

		memset(&upa, 0, sizeof(upa));
		error = got_worktree_rebase_merge_files(&merged_paths,
		    worktree, fileindex, parent_id, commit_id, repo,
		    update_progress, &upa, check_cancelled, NULL);
		if (error)
			goto done;

		print_update_progress_stats(&upa);
		if (upa.conflicts > 0)
			rebase_status = GOT_STATUS_CONFLICT;

		if (rebase_status == GOT_STATUS_CONFLICT) {
			error = show_rebase_merge_conflict(qid->id, repo);
			if (error)
				goto done;
			got_worktree_rebase_pathlist_free(&merged_paths);
			break;
		}

		error = rebase_commit(&merged_paths, worktree, fileindex,
		    tmp_branch, commit_id, repo);
		got_worktree_rebase_pathlist_free(&merged_paths);
		if (error)
			goto done;
	}

	if (rebase_status == GOT_STATUS_CONFLICT) {
		error = got_worktree_rebase_postpone(worktree, fileindex);
		if (error)
			goto done;
		error = got_error_msg(GOT_ERR_CONFLICTS,
		    "conflicts must be resolved before rebasing can continue");
	} else
		error = rebase_complete(worktree, fileindex, branch,
		    new_base_branch, tmp_branch, repo);
done:
	got_object_id_queue_free(&commits);
	free(branch_head_commit_id);
	free(resume_commit_id);
	free(yca_id);
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

__dead static void
usage_histedit(void)
{
	fprintf(stderr, "usage: %s histedit [-a] [-c] [-f] [-F histedit-script] [-m]\n",
	    getprogname());
	exit(1);
}

#define GOT_HISTEDIT_PICK 'p'
#define GOT_HISTEDIT_EDIT 'e'
#define GOT_HISTEDIT_FOLD 'f'
#define GOT_HISTEDIT_DROP 'd'
#define GOT_HISTEDIT_MESG 'm'

static struct got_histedit_cmd {
	unsigned char code;
	const char *name;
	const char *desc;
} got_histedit_cmds[] = {
	{ GOT_HISTEDIT_PICK, "pick", "use commit" },
	{ GOT_HISTEDIT_EDIT, "edit", "use commit but stop for amending" },
	{ GOT_HISTEDIT_FOLD, "fold", "combine with next commit that will "
	    "be used" },
	{ GOT_HISTEDIT_DROP, "drop", "remove commit from history" },
	{ GOT_HISTEDIT_MESG, "mesg",
	    "single-line log message for commit above (open editor if empty)" },
};

struct got_histedit_list_entry {
	TAILQ_ENTRY(got_histedit_list_entry) entry;
	struct got_object_id *commit_id;
	const struct got_histedit_cmd *cmd;
	char *logmsg;
};
TAILQ_HEAD(got_histedit_list, got_histedit_list_entry);

static const struct got_error *
histedit_write_commit(struct got_object_id *commit_id, const char *cmdname,
    FILE *f, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *logmsg = NULL, *id_str = NULL;
	struct got_commit_object *commit = NULL;
	int n;

	err = got_object_open_as_commit(&commit, repo, commit_id);
	if (err)
		goto done;

	err = get_short_logmsg(&logmsg, 34, commit);
	if (err)
		goto done;

	err = got_object_id_str(&id_str, commit_id);
	if (err)
		goto done;

	n = fprintf(f, "%s %s %s\n", cmdname, id_str, logmsg);
	if (n < 0)
		err = got_ferror(f, GOT_ERR_IO);
done:
	if (commit)
		got_object_commit_close(commit);
	free(id_str);
	free(logmsg);
	return err;
}

static const struct got_error *
histedit_write_commit_list(struct got_object_id_queue *commits,
    FILE *f, int edit_logmsg_only, int fold_only, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object_qid *qid;
	const char *histedit_cmd = NULL;

	if (SIMPLEQ_EMPTY(commits))
		return got_error(GOT_ERR_EMPTY_HISTEDIT);

	SIMPLEQ_FOREACH(qid, commits, entry) {
		histedit_cmd = got_histedit_cmds[0].name;
		if (fold_only && SIMPLEQ_NEXT(qid, entry) != NULL)
			histedit_cmd = "fold";
		err = histedit_write_commit(qid->id, histedit_cmd, f, repo);
		if (err)
			break;
		if (edit_logmsg_only) {
			int n = fprintf(f, "%c\n", GOT_HISTEDIT_MESG);
			if (n < 0) {
				err = got_ferror(f, GOT_ERR_IO);
				break;
			}
		}
	}

	return err;
}

static const struct got_error *
write_cmd_list(FILE *f, const char *branch_name,
    struct got_object_id_queue *commits)
{
	const struct got_error *err = NULL;
	size_t i;
	int n;
	char *id_str;
	struct got_object_qid *qid;

	qid = SIMPLEQ_FIRST(commits);
	err = got_object_id_str(&id_str, qid->id);
	if (err)
		return err;

	n = fprintf(f,
	    "# Editing the history of branch '%s' starting at\n"
	    "# commit %s\n"
	    "# Commits will be processed in order from top to "
	    "bottom of this file.\n", branch_name, id_str);
	if (n < 0) {
		err = got_ferror(f, GOT_ERR_IO);
		goto done;
	}

	n = fprintf(f, "# Available histedit commands:\n");
	if (n < 0) {
		err = got_ferror(f, GOT_ERR_IO);
		goto done;
	}

	for (i = 0; i < nitems(got_histedit_cmds); i++) {
		struct got_histedit_cmd *cmd = &got_histedit_cmds[i];
		n = fprintf(f, "#   %s (%c): %s\n", cmd->name, cmd->code,
		    cmd->desc);
		if (n < 0) {
			err = got_ferror(f, GOT_ERR_IO);
			break;
		}
	}
done:
	free(id_str);
	return err;
}

static const struct got_error *
histedit_syntax_error(int lineno)
{
	static char msg[42];
	int ret;

	ret = snprintf(msg, sizeof(msg), "histedit syntax error on line %d",
	    lineno);
	if (ret == -1 || ret >= sizeof(msg))
		return got_error(GOT_ERR_HISTEDIT_SYNTAX);

	return got_error_msg(GOT_ERR_HISTEDIT_SYNTAX, msg);
}

static const struct got_error *
append_folded_commit_msg(char **new_msg, struct got_histedit_list_entry *hle,
    char *logmsg, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_commit_object *folded_commit = NULL;
	char *id_str, *folded_logmsg = NULL;

	err = got_object_id_str(&id_str, hle->commit_id);
	if (err)
		return err;

	err = got_object_open_as_commit(&folded_commit, repo, hle->commit_id);
	if (err)
		goto done;

	err = got_object_commit_get_logmsg(&folded_logmsg, folded_commit);
	if (err)
		goto done;
	if (asprintf(new_msg, "%s%s# log message of folded commit %s: %s",
	    logmsg ? logmsg : "", logmsg ? "\n" : "", id_str,
	    folded_logmsg) == -1) {
		err = got_error_from_errno("asprintf");
	}
done:
	if (folded_commit)
		got_object_commit_close(folded_commit);
	free(id_str);
	free(folded_logmsg);
	return err;
}

static struct got_histedit_list_entry *
get_folded_commits(struct got_histedit_list_entry *hle)
{
	struct got_histedit_list_entry *prev, *folded = NULL;

	prev = TAILQ_PREV(hle, got_histedit_list, entry);
	while (prev && (prev->cmd->code == GOT_HISTEDIT_FOLD ||
	    prev->cmd->code == GOT_HISTEDIT_DROP)) {
		if (prev->cmd->code == GOT_HISTEDIT_FOLD)
			folded = prev;
		prev = TAILQ_PREV(prev, got_histedit_list, entry);
	}

	return folded;
}

static const struct got_error *
histedit_edit_logmsg(struct got_histedit_list_entry *hle,
    struct got_repository *repo)
{
	char *logmsg_path = NULL, *id_str = NULL, *orig_logmsg = NULL;
	char *logmsg = NULL, *new_msg = NULL, *editor = NULL;
	const struct got_error *err = NULL;
	struct got_commit_object *commit = NULL;
	int logmsg_len;
	int fd;
	struct got_histedit_list_entry *folded = NULL;

	err = got_object_open_as_commit(&commit, repo, hle->commit_id);
	if (err)
		return err;

	folded = get_folded_commits(hle);
	if (folded) {
		while (folded != hle) {
			if (folded->cmd->code == GOT_HISTEDIT_DROP) {
				folded = TAILQ_NEXT(folded, entry);
				continue;
			}
			err = append_folded_commit_msg(&new_msg, folded,
			    logmsg, repo);
			if (err)
				goto done;
			free(logmsg);
			logmsg = new_msg;
			folded = TAILQ_NEXT(folded, entry);
		}
	}

	err = got_object_id_str(&id_str, hle->commit_id);
	if (err)
		goto done;
	err = got_object_commit_get_logmsg(&orig_logmsg, commit);
	if (err)
		goto done;
	logmsg_len = asprintf(&new_msg,
	    "%s\n# original log message of commit %s: %s",
	    logmsg ? logmsg : "", id_str, orig_logmsg);
	if (logmsg_len == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}
	free(logmsg);
	logmsg = new_msg;

	err = got_object_id_str(&id_str, hle->commit_id);
	if (err)
		goto done;

	err = got_opentemp_named_fd(&logmsg_path, &fd,
	    GOT_TMPDIR_STR "/got-logmsg");
	if (err)
		goto done;

	write(fd, logmsg, logmsg_len);
	close(fd);

	err = get_editor(&editor);
	if (err)
		goto done;

	err = edit_logmsg(&hle->logmsg, editor, logmsg_path, logmsg,
	    logmsg_len, 0);
	if (err) {
		if (err->code != GOT_ERR_COMMIT_MSG_EMPTY)
			goto done;
		err = NULL;
		hle->logmsg = strdup(new_msg);
		if (hle->logmsg == NULL)
			err = got_error_from_errno("strdup");
	}
done:
	if (logmsg_path && unlink(logmsg_path) != 0 && err == NULL)
		err = got_error_from_errno2("unlink", logmsg_path);
	free(logmsg_path);
	free(logmsg);
	free(orig_logmsg);
	free(editor);
	if (commit)
		got_object_commit_close(commit);
	return err;
}

static const struct got_error *
histedit_parse_list(struct got_histedit_list *histedit_cmds,
    FILE *f, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *line = NULL, *p, *end;
	size_t i, size;
	ssize_t len;
	int lineno = 0;
	const struct got_histedit_cmd *cmd;
	struct got_object_id *commit_id = NULL;
	struct got_histedit_list_entry *hle = NULL;

	for (;;) {
		len = getline(&line, &size, f);
		if (len == -1) {
			const struct got_error *getline_err;
			if (feof(f))
				break;
			getline_err = got_error_from_errno("getline");
			err = got_ferror(f, getline_err->code);
			break;
		}
		lineno++;
		p = line;
		while (isspace((unsigned char)p[0]))
			p++;
		if (p[0] == '#' || p[0] == '\0') {
			free(line);
			line = NULL;
			continue;
		}
		cmd = NULL;
		for (i = 0; i < nitems(got_histedit_cmds); i++) {
			cmd = &got_histedit_cmds[i];
			if (strncmp(cmd->name, p, strlen(cmd->name)) == 0 &&
			    isspace((unsigned char)p[strlen(cmd->name)])) {
				p += strlen(cmd->name);
				break;
			}
			if (p[0] == cmd->code && isspace((unsigned char)p[1])) {
				p++;
				break;
			}
		}
		if (i == nitems(got_histedit_cmds)) {
			err = histedit_syntax_error(lineno);
			break;
		}
		while (isspace((unsigned char)p[0]))
			p++;
		if (cmd->code == GOT_HISTEDIT_MESG) {
			if (hle == NULL || hle->logmsg != NULL) {
				err = got_error(GOT_ERR_HISTEDIT_CMD);
				break;
			}
			if (p[0] == '\0') {
				err = histedit_edit_logmsg(hle, repo);
				if (err)
					break;
			} else {
				hle->logmsg = strdup(p);
				if (hle->logmsg == NULL) {
					err = got_error_from_errno("strdup");
					break;
				}
			}
			free(line);
			line = NULL;
			continue;
		} else {
			end = p;
			while (end[0] && !isspace((unsigned char)end[0]))
				end++;
			*end = '\0';

			err = got_object_resolve_id_str(&commit_id, repo, p);
			if (err) {
				/* override error code */
				err = histedit_syntax_error(lineno);
				break;
			}
		}
		hle = malloc(sizeof(*hle));
		if (hle == NULL) {
			err = got_error_from_errno("malloc");
			break;
		}
		hle->cmd = cmd;
		hle->commit_id = commit_id;
		hle->logmsg = NULL;
		commit_id = NULL;
		free(line);
		line = NULL;
		TAILQ_INSERT_TAIL(histedit_cmds, hle, entry);
	}

	free(line);
	free(commit_id);
	return err;
}

static const struct got_error *
histedit_check_script(struct got_histedit_list *histedit_cmds,
    struct got_object_id_queue *commits, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object_qid *qid;
	struct got_histedit_list_entry *hle;
	static char msg[92];
	char *id_str;

	if (TAILQ_EMPTY(histedit_cmds))
		return got_error_msg(GOT_ERR_EMPTY_HISTEDIT,
		    "histedit script contains no commands");
	if (SIMPLEQ_EMPTY(commits))
		return got_error(GOT_ERR_EMPTY_HISTEDIT);

	TAILQ_FOREACH(hle, histedit_cmds, entry) {
		struct got_histedit_list_entry *hle2;
		TAILQ_FOREACH(hle2, histedit_cmds, entry) {
			if (hle == hle2)
				continue;
			if (got_object_id_cmp(hle->commit_id,
			    hle2->commit_id) != 0)
				continue;
			err = got_object_id_str(&id_str, hle->commit_id);
			if (err)
				return err;
			snprintf(msg, sizeof(msg), "commit %s is listed "
			    "more than once in histedit script", id_str);
			free(id_str);
			return got_error_msg(GOT_ERR_HISTEDIT_CMD, msg);
		}
	}

	SIMPLEQ_FOREACH(qid, commits, entry) {
		TAILQ_FOREACH(hle, histedit_cmds, entry) {
			if (got_object_id_cmp(qid->id, hle->commit_id) == 0)
				break;
		}
		if (hle == NULL) {
			err = got_object_id_str(&id_str, qid->id);
			if (err)
				return err;
			snprintf(msg, sizeof(msg),
			    "commit %s missing from histedit script", id_str);
			free(id_str);
			return got_error_msg(GOT_ERR_HISTEDIT_CMD, msg);
		}
	}

	hle = TAILQ_LAST(histedit_cmds, got_histedit_list);
	if (hle && hle->cmd->code == GOT_HISTEDIT_FOLD)
		return got_error_msg(GOT_ERR_HISTEDIT_CMD,
		    "last commit in histedit script cannot be folded");

	return NULL;
}

static const struct got_error *
histedit_run_editor(struct got_histedit_list *histedit_cmds,
    const char *path, struct got_object_id_queue *commits,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *editor;
	FILE *f = NULL;

	err = get_editor(&editor);
	if (err)
		return err;

	if (spawn_editor(editor, path) == -1) {
		err = got_error_from_errno("failed spawning editor");
		goto done;
	}

	f = fopen(path, "r");
	if (f == NULL) {
		err = got_error_from_errno("fopen");
		goto done;
	}
	err = histedit_parse_list(histedit_cmds, f, repo);
	if (err)
		goto done;

	err = histedit_check_script(histedit_cmds, commits, repo);
done:
	if (f && fclose(f) != 0 && err == NULL)
		err = got_error_from_errno("fclose");
	free(editor);
	return err;
}

static const struct got_error *
histedit_edit_list_retry(struct got_histedit_list *, const struct got_error *,
    struct got_object_id_queue *, const char *, const char *,
    struct got_repository *);

static const struct got_error *
histedit_edit_script(struct got_histedit_list *histedit_cmds,
    struct got_object_id_queue *commits, const char *branch_name,
    int edit_logmsg_only, int fold_only, struct got_repository *repo)
{
	const struct got_error *err;
	FILE *f = NULL;
	char *path = NULL;

	err = got_opentemp_named(&path, &f, "got-histedit");
	if (err)
		return err;

	err = write_cmd_list(f, branch_name, commits);
	if (err)
		goto done;

	err = histedit_write_commit_list(commits, f, edit_logmsg_only,
	    fold_only, repo);
	if (err)
		goto done;

	if (edit_logmsg_only || fold_only) {
		rewind(f);
		err = histedit_parse_list(histedit_cmds, f, repo);
	} else {
		if (fclose(f) != 0) {
			err = got_error_from_errno("fclose");
			goto done;
		}
		f = NULL;
		err = histedit_run_editor(histedit_cmds, path, commits, repo);
		if (err) {
			if (err->code != GOT_ERR_HISTEDIT_SYNTAX &&
			    err->code != GOT_ERR_HISTEDIT_CMD)
				goto done;
			err = histedit_edit_list_retry(histedit_cmds, err,
			    commits, path, branch_name, repo);
		}
	}
done:
	if (f && fclose(f) != 0 && err == NULL)
		err = got_error_from_errno("fclose");
	if (path && unlink(path) != 0 && err == NULL)
		err = got_error_from_errno2("unlink", path);
	free(path);
	return err;
}

static const struct got_error *
histedit_save_list(struct got_histedit_list *histedit_cmds,
    struct got_worktree *worktree, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *path = NULL;
	FILE *f = NULL;
	struct got_histedit_list_entry *hle;
	struct got_commit_object *commit = NULL;

	err = got_worktree_get_histedit_script_path(&path, worktree);
	if (err)
		return err;

	f = fopen(path, "w");
	if (f == NULL) {
		err = got_error_from_errno2("fopen", path);
		goto done;
	}
	TAILQ_FOREACH(hle, histedit_cmds, entry) {
		err = histedit_write_commit(hle->commit_id, hle->cmd->name, f,
		    repo);
		if (err)
			break;

		if (hle->logmsg) {
			int n = fprintf(f, "%c %s\n",
			    GOT_HISTEDIT_MESG, hle->logmsg);
			if (n < 0) {
				err = got_ferror(f, GOT_ERR_IO);
				break;
			}
		}
	}
done:
	if (f && fclose(f) != 0 && err == NULL)
		err = got_error_from_errno("fclose");
	free(path);
	if (commit)
		got_object_commit_close(commit);
	return err;
}

void
histedit_free_list(struct got_histedit_list *histedit_cmds)
{
	struct got_histedit_list_entry *hle;

	while ((hle = TAILQ_FIRST(histedit_cmds))) {
		TAILQ_REMOVE(histedit_cmds, hle, entry);
		free(hle);
	}
}

static const struct got_error *
histedit_load_list(struct got_histedit_list *histedit_cmds,
    const char *path, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	FILE *f = NULL;

	f = fopen(path, "r");
	if (f == NULL) {
		err = got_error_from_errno2("fopen", path);
		goto done;
	}

	err = histedit_parse_list(histedit_cmds, f, repo);
done:
	if (f && fclose(f) != 0 && err == NULL)
		err = got_error_from_errno("fclose");
	return err;
}

static const struct got_error *
histedit_edit_list_retry(struct got_histedit_list *histedit_cmds,
    const struct got_error *edit_err, struct got_object_id_queue *commits,
    const char *path, const char *branch_name, struct got_repository *repo)
{
	const struct got_error *err = NULL, *prev_err = edit_err;
	int resp = ' ';

	while (resp != 'c' && resp != 'r' && resp != 'a') {
		printf("%s: %s\n(c)ontinue editing, (r)estart editing, "
		    "or (a)bort: ", getprogname(), prev_err->msg);
		resp = getchar();
		if (resp == '\n')
			resp = getchar();
		if (resp == 'c') {
			histedit_free_list(histedit_cmds);
			err = histedit_run_editor(histedit_cmds, path, commits,
			    repo);
			if (err) {
				if (err->code != GOT_ERR_HISTEDIT_SYNTAX &&
				    err->code != GOT_ERR_HISTEDIT_CMD)
					break;
				prev_err = err;
				resp = ' ';
				continue;
			}
			break;
		} else if (resp == 'r') {
			histedit_free_list(histedit_cmds);
			err = histedit_edit_script(histedit_cmds,
			    commits, branch_name, 0, 0, repo);
			if (err) {
				if (err->code != GOT_ERR_HISTEDIT_SYNTAX &&
				    err->code != GOT_ERR_HISTEDIT_CMD)
					break;
				prev_err = err;
				resp = ' ';
				continue;
			}
			break;
		} else if (resp == 'a') {
			err = got_error(GOT_ERR_HISTEDIT_CANCEL);
			break;
		} else
			printf("invalid response '%c'\n", resp);
	}

	return err;
}

static const struct got_error *
histedit_complete(struct got_worktree *worktree,
    struct got_fileindex *fileindex, struct got_reference *tmp_branch,
    struct got_reference *branch, struct got_repository *repo)
{
	printf("Switching work tree to %s\n",
	    got_ref_get_symref_target(branch));
	return got_worktree_histedit_complete(worktree, fileindex, tmp_branch,
	    branch, repo);
}

static const struct got_error *
show_histedit_progress(struct got_commit_object *commit,
    struct got_histedit_list_entry *hle, struct got_object_id *new_id)
{
	const struct got_error *err;
	char *old_id_str = NULL, *new_id_str = NULL, *logmsg = NULL;

	err = got_object_id_str(&old_id_str, hle->commit_id);
	if (err)
		goto done;

	if (new_id) {
		err = got_object_id_str(&new_id_str, new_id);
		if (err)
			goto done;
	}

	old_id_str[12] = '\0';
	if (new_id_str)
		new_id_str[12] = '\0';

	if (hle->logmsg) {
		logmsg = strdup(hle->logmsg);
		if (logmsg == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
		trim_logmsg(logmsg, 42);
	} else {
		err = get_short_logmsg(&logmsg, 42, commit);
		if (err)
			goto done;
	}

	switch (hle->cmd->code) {
	case GOT_HISTEDIT_PICK:
	case GOT_HISTEDIT_EDIT:
		printf("%s -> %s: %s\n", old_id_str,
		    new_id_str ? new_id_str : "no-op change", logmsg);
		break;
	case GOT_HISTEDIT_DROP:
	case GOT_HISTEDIT_FOLD:
		printf("%s ->  %s commit: %s\n", old_id_str, hle->cmd->name,
		    logmsg);
		break;
	default:
		break;
	}
done:
	free(old_id_str);
	free(new_id_str);
	return err;
}

static const struct got_error *
histedit_commit(struct got_pathlist_head *merged_paths,
    struct got_worktree *worktree, struct got_fileindex *fileindex,
    struct got_reference *tmp_branch, struct got_histedit_list_entry *hle,
    struct got_repository *repo)
{
	const struct got_error *err;
	struct got_commit_object *commit;
	struct got_object_id *new_commit_id;

	if ((hle->cmd->code == GOT_HISTEDIT_EDIT || get_folded_commits(hle))
	    && hle->logmsg == NULL) {
		err = histedit_edit_logmsg(hle, repo);
		if (err)
			return err;
	}

	err = got_object_open_as_commit(&commit, repo, hle->commit_id);
	if (err)
		return err;

	err = got_worktree_histedit_commit(&new_commit_id, merged_paths,
	    worktree, fileindex, tmp_branch, commit, hle->commit_id,
	    hle->logmsg, repo);
	if (err) {
		if (err->code != GOT_ERR_COMMIT_NO_CHANGES)
			goto done;
		err = show_histedit_progress(commit, hle, NULL);
	} else {
		err = show_histedit_progress(commit, hle, new_commit_id);
		free(new_commit_id);
	}
done:
	got_object_commit_close(commit);
	return err;
}

static const struct got_error *
histedit_skip_commit(struct got_histedit_list_entry *hle,
    struct got_worktree *worktree, struct got_repository *repo)
{
	const struct got_error *error;
	struct got_commit_object *commit;

	error = got_worktree_histedit_skip_commit(worktree, hle->commit_id,
	    repo);
	if (error)
		return error;

	error = got_object_open_as_commit(&commit, repo, hle->commit_id);
	if (error)
		return error;

	error = show_histedit_progress(commit, hle, NULL);
	got_object_commit_close(commit);
	return error;
}

static const struct got_error *
check_local_changes(void *arg, unsigned char status,
    unsigned char staged_status, const char *path,
    struct got_object_id *blob_id, struct got_object_id *staged_blob_id,
    struct got_object_id *commit_id, int dirfd, const char *de_name)
{
	int *have_local_changes = arg;

	switch (status) {
	case GOT_STATUS_ADD:
	case GOT_STATUS_DELETE:
	case GOT_STATUS_MODIFY:
	case GOT_STATUS_CONFLICT:
		*have_local_changes = 1;
		return got_error(GOT_ERR_CANCELLED);
	default:
		break;
	}

	switch (staged_status) {
	case GOT_STATUS_ADD:
	case GOT_STATUS_DELETE:
	case GOT_STATUS_MODIFY:
		*have_local_changes = 1;
		return got_error(GOT_ERR_CANCELLED);
	default:
		break;
	}

	return NULL;
}

static const struct got_error *
cmd_histedit(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_worktree *worktree = NULL;
	struct got_fileindex *fileindex = NULL;
	struct got_repository *repo = NULL;
	char *cwd = NULL;
	struct got_reference *branch = NULL;
	struct got_reference *tmp_branch = NULL;
	struct got_object_id *resume_commit_id = NULL;
	struct got_object_id *base_commit_id = NULL;
	struct got_object_id *head_commit_id = NULL;
	struct got_commit_object *commit = NULL;
	int ch, rebase_in_progress = 0;
	struct got_update_progress_arg upa;
	int edit_in_progress = 0, abort_edit = 0, continue_edit = 0;
	int edit_logmsg_only = 0, fold_only = 0;
	const char *edit_script_path = NULL;
	unsigned char rebase_status = GOT_STATUS_NO_CHANGE;
	struct got_object_id_queue commits;
	struct got_pathlist_head merged_paths;
	const struct got_object_id_queue *parent_ids;
	struct got_object_qid *pid;
	struct got_histedit_list histedit_cmds;
	struct got_histedit_list_entry *hle;

	SIMPLEQ_INIT(&commits);
	TAILQ_INIT(&histedit_cmds);
	TAILQ_INIT(&merged_paths);
	memset(&upa, 0, sizeof(upa));

	while ((ch = getopt(argc, argv, "acfF:m")) != -1) {
		switch (ch) {
		case 'a':
			abort_edit = 1;
			break;
		case 'c':
			continue_edit = 1;
			break;
		case 'f':
			fold_only = 1;
			break;
		case 'F':
			edit_script_path = optarg;
			break;
		case 'm':
			edit_logmsg_only = 1;
			break;
		default:
			usage_histedit();
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
	if (abort_edit && continue_edit)
		option_conflict('a', 'c');
	if (edit_script_path && edit_logmsg_only)
		option_conflict('F', 'm');
	if (abort_edit && edit_logmsg_only)
		option_conflict('a', 'm');
	if (continue_edit && edit_logmsg_only)
		option_conflict('c', 'm');
	if (abort_edit && fold_only)
		option_conflict('a', 'f');
	if (continue_edit && fold_only)
		option_conflict('c', 'f');
	if (fold_only && edit_logmsg_only)
		option_conflict('f', 'm');
	if (edit_script_path && fold_only)
		option_conflict('F', 'f');
	if (argc != 0)
		usage_histedit();

	/*
	 * This command cannot apply unveil(2) in all cases because the
	 * user may choose to run an editor to edit the histedit script
	 * and to edit individual commit log messages.
	 * unveil(2) traverses exec(2); if an editor is used we have to
	 * apply unveil after edit script and log messages have been written.
	 * XXX TODO: Make use of unveil(2) where possible.
	 */

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}
	error = got_worktree_open(&worktree, cwd);
	if (error) {
		if (error->code == GOT_ERR_NOT_WORKTREE)
			error = wrap_not_worktree_error(error, "histedit", cwd);
		goto done;
	}

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree),
	    NULL);
	if (error != NULL)
		goto done;

	error = got_worktree_rebase_in_progress(&rebase_in_progress, worktree);
	if (error)
		goto done;
	if (rebase_in_progress) {
		error = got_error(GOT_ERR_REBASING);
		goto done;
	}

	error = got_worktree_histedit_in_progress(&edit_in_progress, worktree);
	if (error)
		goto done;

	if (edit_in_progress && edit_logmsg_only) {
		error = got_error_msg(GOT_ERR_HISTEDIT_BUSY,
		    "histedit operation is in progress in this "
		    "work tree and must be continued or aborted "
		    "before the -m option can be used");
		goto done;
	}
	if (edit_in_progress && fold_only) {
		error = got_error_msg(GOT_ERR_HISTEDIT_BUSY,
		    "histedit operation is in progress in this "
		    "work tree and must be continued or aborted "
		    "before the -f option can be used");
		goto done;
	}

	if (edit_in_progress && abort_edit) {
		error = got_worktree_histedit_continue(&resume_commit_id,
		    &tmp_branch, &branch, &base_commit_id, &fileindex,
		    worktree, repo);
		if (error)
			goto done;
		printf("Switching work tree to %s\n",
		    got_ref_get_symref_target(branch));
		error = got_worktree_histedit_abort(worktree, fileindex, repo,
		    branch, base_commit_id, update_progress, &upa);
		if (error)
			goto done;
		printf("Histedit of %s aborted\n",
		    got_ref_get_symref_target(branch));
		print_update_progress_stats(&upa);
		goto done; /* nothing else to do */
	} else if (abort_edit) {
		error = got_error(GOT_ERR_NOT_HISTEDIT);
		goto done;
	}

	if (continue_edit) {
		char *path;

		if (!edit_in_progress) {
			error = got_error(GOT_ERR_NOT_HISTEDIT);
			goto done;
		}

		error = got_worktree_get_histedit_script_path(&path, worktree);
		if (error)
			goto done;

		error = histedit_load_list(&histedit_cmds, path, repo);
		free(path);
		if (error)
			goto done;

		error = got_worktree_histedit_continue(&resume_commit_id,
		    &tmp_branch, &branch, &base_commit_id, &fileindex,
		    worktree, repo);
		if (error)
			goto done;

		error = got_ref_resolve(&head_commit_id, repo, branch);
		if (error)
			goto done;

		error = got_object_open_as_commit(&commit, repo,
		    head_commit_id);
		if (error)
			goto done;
		parent_ids = got_object_commit_get_parent_ids(commit);
		pid = SIMPLEQ_FIRST(parent_ids);
		if (pid == NULL) {
			error = got_error(GOT_ERR_EMPTY_HISTEDIT);
			goto done;
		}
		error = collect_commits(&commits, head_commit_id, pid->id,
		    base_commit_id, got_worktree_get_path_prefix(worktree),
		    GOT_ERR_HISTEDIT_PATH, repo);
		got_object_commit_close(commit);
		commit = NULL;
		if (error)
			goto done;
	} else {
		if (edit_in_progress) {
			error = got_error(GOT_ERR_HISTEDIT_BUSY);
			goto done;
		}

		error = got_ref_open(&branch, repo,
		    got_worktree_get_head_ref_name(worktree), 0);
		if (error != NULL)
			goto done;

		if (strncmp(got_ref_get_name(branch), "refs/heads/", 11) != 0) {
			error = got_error_msg(GOT_ERR_COMMIT_BRANCH,
			    "will not edit commit history of a branch outside "
			    "the \"refs/heads/\" reference namespace");
			goto done;
		}

		error = got_ref_resolve(&head_commit_id, repo, branch);
		got_ref_close(branch);
		branch = NULL;
		if (error)
			goto done;

		error = got_object_open_as_commit(&commit, repo,
		    head_commit_id);
		if (error)
			goto done;
		parent_ids = got_object_commit_get_parent_ids(commit);
		pid = SIMPLEQ_FIRST(parent_ids);
		if (pid == NULL) {
			error = got_error(GOT_ERR_EMPTY_HISTEDIT);
			goto done;
		}
		error = collect_commits(&commits, head_commit_id, pid->id,
		    got_worktree_get_base_commit_id(worktree),
		    got_worktree_get_path_prefix(worktree),
		    GOT_ERR_HISTEDIT_PATH, repo);
		got_object_commit_close(commit);
		commit = NULL;
		if (error)
			goto done;

		if (SIMPLEQ_EMPTY(&commits)) {
			error = got_error(GOT_ERR_EMPTY_HISTEDIT);
			goto done;
		}

		error = got_worktree_histedit_prepare(&tmp_branch, &branch,
		    &base_commit_id, &fileindex, worktree, repo);
		if (error)
			goto done;

		if (edit_script_path) {
			error = histedit_load_list(&histedit_cmds,
			    edit_script_path, repo);
			if (error) {
				got_worktree_histedit_abort(worktree, fileindex,
				    repo, branch, base_commit_id,
				    update_progress, &upa);
				print_update_progress_stats(&upa);
				goto done;
			}
		} else {
			const char *branch_name;
			branch_name = got_ref_get_symref_target(branch);
			if (strncmp(branch_name, "refs/heads/", 11) == 0)
				branch_name += 11;
			error = histedit_edit_script(&histedit_cmds, &commits,
			    branch_name, edit_logmsg_only, fold_only, repo);
			if (error) {
				got_worktree_histedit_abort(worktree, fileindex,
				    repo, branch, base_commit_id,
				    update_progress, &upa);
				print_update_progress_stats(&upa);
				goto done;
			}

		}

		error = histedit_save_list(&histedit_cmds, worktree,
		    repo);
		if (error) {
			got_worktree_histedit_abort(worktree, fileindex,
			    repo, branch, base_commit_id,
			    update_progress, &upa);
			print_update_progress_stats(&upa);
			goto done;
		}

	}

	error = histedit_check_script(&histedit_cmds, &commits, repo);
	if (error)
		goto done;

	TAILQ_FOREACH(hle, &histedit_cmds, entry) {
		if (resume_commit_id) {
			if (got_object_id_cmp(hle->commit_id,
			    resume_commit_id) != 0)
				continue;

			resume_commit_id = NULL;
			if (hle->cmd->code == GOT_HISTEDIT_DROP ||
			    hle->cmd->code == GOT_HISTEDIT_FOLD) {
				error = histedit_skip_commit(hle, worktree,
				    repo);
				if (error)
					goto done;
			} else {
				struct got_pathlist_head paths;
				int have_changes = 0;

				TAILQ_INIT(&paths);
				error = got_pathlist_append(&paths, "", NULL);
				if (error)
					goto done;
				error = got_worktree_status(worktree, &paths,
				    repo, check_local_changes, &have_changes,
				    check_cancelled, NULL);
				got_pathlist_free(&paths);
				if (error) {
					if (error->code != GOT_ERR_CANCELLED)
						goto done;
					if (sigint_received || sigpipe_received)
						goto done;
				}
				if (have_changes) {
					error = histedit_commit(NULL, worktree,
					    fileindex, tmp_branch, hle, repo);
					if (error)
						goto done;
				} else {
					error = got_object_open_as_commit(
					    &commit, repo, hle->commit_id);
					if (error)
						goto done;
					error = show_histedit_progress(commit,
					    hle, NULL);
					got_object_commit_close(commit);
					commit = NULL;
					if (error)
						goto done;
				}
			}
			continue;
		}

		if (hle->cmd->code == GOT_HISTEDIT_DROP) {
			error = histedit_skip_commit(hle, worktree, repo);
			if (error)
				goto done;
			continue;
		}

		error = got_object_open_as_commit(&commit, repo,
		    hle->commit_id);
		if (error)
			goto done;
		parent_ids = got_object_commit_get_parent_ids(commit);
		pid = SIMPLEQ_FIRST(parent_ids);

		error = got_worktree_histedit_merge_files(&merged_paths,
		    worktree, fileindex, pid->id, hle->commit_id, repo,
		    update_progress, &upa, check_cancelled, NULL);
		if (error)
			goto done;
		got_object_commit_close(commit);
		commit = NULL;

		print_update_progress_stats(&upa);
		if (upa.conflicts > 0)
			rebase_status = GOT_STATUS_CONFLICT;

		if (rebase_status == GOT_STATUS_CONFLICT) {
			error = show_rebase_merge_conflict(hle->commit_id,
			    repo);
			if (error)
				goto done;
			got_worktree_rebase_pathlist_free(&merged_paths);
			break;
		}

		if (hle->cmd->code == GOT_HISTEDIT_EDIT) {
			char *id_str;
			error = got_object_id_str(&id_str, hle->commit_id);
			if (error)
				goto done;
			printf("Stopping histedit for amending commit %s\n",
			    id_str);
			free(id_str);
			got_worktree_rebase_pathlist_free(&merged_paths);
			error = got_worktree_histedit_postpone(worktree,
			    fileindex);
			goto done;
		}

		if (hle->cmd->code == GOT_HISTEDIT_FOLD) {
			error = histedit_skip_commit(hle, worktree, repo);
			if (error)
				goto done;
			continue;
		}

		error = histedit_commit(&merged_paths, worktree, fileindex,
		    tmp_branch, hle, repo);
		got_worktree_rebase_pathlist_free(&merged_paths);
		if (error)
			goto done;
	}

	if (rebase_status == GOT_STATUS_CONFLICT) {
		error = got_worktree_histedit_postpone(worktree, fileindex);
		if (error)
			goto done;
		error = got_error_msg(GOT_ERR_CONFLICTS,
		    "conflicts must be resolved before histedit can continue");
	} else
		error = histedit_complete(worktree, fileindex, tmp_branch,
		    branch, repo);
done:
	got_object_id_queue_free(&commits);
	histedit_free_list(&histedit_cmds);
	free(head_commit_id);
	free(base_commit_id);
	free(resume_commit_id);
	if (commit)
		got_object_commit_close(commit);
	if (branch)
		got_ref_close(branch);
	if (tmp_branch)
		got_ref_close(tmp_branch);
	if (worktree)
		got_worktree_close(worktree);
	if (repo)
		got_repo_close(repo);
	return error;
}

__dead static void
usage_integrate(void)
{
	fprintf(stderr, "usage: %s integrate branch\n", getprogname());
	exit(1);
}

static const struct got_error *
cmd_integrate(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *cwd = NULL, *refname = NULL, *base_refname = NULL;
	const char *branch_arg = NULL;
	struct got_reference *branch_ref = NULL, *base_branch_ref = NULL;
	struct got_fileindex *fileindex = NULL;
	struct got_object_id *commit_id = NULL, *base_commit_id = NULL;
	int ch;
	struct got_update_progress_arg upa;

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			usage_integrate();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage_integrate();
	branch_arg = argv[0];
#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr flock proc exec sendfd "
	    "unveil", NULL) == -1)
		err(1, "pledge");
#endif
	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_worktree_open(&worktree, cwd);
	if (error) {
		if (error->code == GOT_ERR_NOT_WORKTREE)
			error = wrap_not_worktree_error(error, "integrate",
			    cwd);
		goto done;
	}

	error = check_rebase_or_histedit_in_progress(worktree);
	if (error)
		goto done;

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree),
	    NULL);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 0,
	    got_worktree_get_root_path(worktree));
	if (error)
		goto done;

	if (asprintf(&refname, "refs/heads/%s", branch_arg) == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}

	error = got_worktree_integrate_prepare(&fileindex, &branch_ref,
	    &base_branch_ref, worktree, refname, repo);
	if (error)
		goto done;

	refname = strdup(got_ref_get_name(branch_ref));
	if (refname == NULL) {
		error = got_error_from_errno("strdup");
		got_worktree_integrate_abort(worktree, fileindex, repo,
		    branch_ref, base_branch_ref);
		goto done;
	}
	base_refname = strdup(got_ref_get_name(base_branch_ref));
	if (base_refname == NULL) {
		error = got_error_from_errno("strdup");
		got_worktree_integrate_abort(worktree, fileindex, repo,
		    branch_ref, base_branch_ref);
		goto done;
	}

	error = got_ref_resolve(&commit_id, repo, branch_ref);
	if (error)
		goto done;

	error = got_ref_resolve(&base_commit_id, repo, base_branch_ref);
	if (error)
		goto done;

	if (got_object_id_cmp(commit_id, base_commit_id) == 0) {
		error = got_error_msg(GOT_ERR_SAME_BRANCH,
		    "specified branch has already been integrated");
		got_worktree_integrate_abort(worktree, fileindex, repo,
		    branch_ref, base_branch_ref);
		goto done;
	}

	error = check_linear_ancestry(commit_id, base_commit_id, 1, repo);
	if (error) {
		if (error->code == GOT_ERR_ANCESTRY)
			error = got_error(GOT_ERR_REBASE_REQUIRED);
		got_worktree_integrate_abort(worktree, fileindex, repo,
		    branch_ref, base_branch_ref);
		goto done;
	}

	memset(&upa, 0, sizeof(upa));
	error = got_worktree_integrate_continue(worktree, fileindex, repo,
	    branch_ref, base_branch_ref, update_progress, &upa,
	    check_cancelled, NULL);
	if (error)
		goto done;

	printf("Integrated %s into %s\n", refname, base_refname);
	print_update_progress_stats(&upa);
done:
	if (repo)
		got_repo_close(repo);
	if (worktree)
		got_worktree_close(worktree);
	free(cwd);
	free(base_commit_id);
	free(commit_id);
	free(refname);
	free(base_refname);
	return error;
}

__dead static void
usage_stage(void)
{
	fprintf(stderr, "usage: %s stage [-l] | [-p] [-F response-script] "
	    "[-S] [file-path ...]\n",
	    getprogname());
	exit(1);
}

static const struct got_error *
print_stage(void *arg, unsigned char status, unsigned char staged_status,
    const char *path, struct got_object_id *blob_id,
    struct got_object_id *staged_blob_id, struct got_object_id *commit_id,
    int dirfd, const char *de_name)
{
	const struct got_error *err = NULL;
	char *id_str = NULL;

	if (staged_status != GOT_STATUS_ADD &&
	    staged_status != GOT_STATUS_MODIFY &&
	    staged_status != GOT_STATUS_DELETE)
		return NULL;

	if (staged_status == GOT_STATUS_ADD ||
	    staged_status == GOT_STATUS_MODIFY)
		err = got_object_id_str(&id_str, staged_blob_id);
	else
		err = got_object_id_str(&id_str, blob_id);
	if (err)
		return err;

	printf("%s %c %s\n", id_str, staged_status, path);
	free(id_str);
	return NULL;
}

static const struct got_error *
cmd_stage(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *cwd = NULL;
	struct got_pathlist_head paths;
	struct got_pathlist_entry *pe;
	int ch, list_stage = 0, pflag = 0, allow_bad_symlinks = 0;
	FILE *patch_script_file = NULL;
	const char *patch_script_path = NULL;
	struct choose_patch_arg cpa;

	TAILQ_INIT(&paths);

	while ((ch = getopt(argc, argv, "lpF:S")) != -1) {
		switch (ch) {
		case 'l':
			list_stage = 1;
			break;
		case 'p':
			pflag = 1;
			break;
		case 'F':
			patch_script_path = optarg;
			break;
		case 'S':
			allow_bad_symlinks = 1;
			break;
		default:
			usage_stage();
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
	if (list_stage && (pflag || patch_script_path))
		errx(1, "-l option cannot be used with other options");
	if (patch_script_path && !pflag)
		errx(1, "-F option can only be used together with -p option");

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_worktree_open(&worktree, cwd);
	if (error) {
		if (error->code == GOT_ERR_NOT_WORKTREE)
			error = wrap_not_worktree_error(error, "stage", cwd);
		goto done;
	}

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree),
	    NULL);
	if (error != NULL)
		goto done;

	if (patch_script_path) {
		patch_script_file = fopen(patch_script_path, "r");
		if (patch_script_file == NULL) {
			error = got_error_from_errno2("fopen",
			    patch_script_path);
			goto done;
		}
	}
	error = apply_unveil(got_repo_get_path(repo), 0,
	    got_worktree_get_root_path(worktree));
	if (error)
		goto done;

	error = get_worktree_paths_from_argv(&paths, argc, argv, worktree);
	if (error)
		goto done;

	if (list_stage)
		error = got_worktree_status(worktree, &paths, repo,
		    print_stage, NULL, check_cancelled, NULL);
	else {
		cpa.patch_script_file = patch_script_file;
		cpa.action = "stage";
		error = got_worktree_stage(worktree, &paths,
		    pflag ? NULL : print_status, NULL,
		    pflag ? choose_patch : NULL, &cpa,
		    allow_bad_symlinks, repo);
	}
done:
	if (patch_script_file && fclose(patch_script_file) == EOF &&
	    error == NULL)
		error = got_error_from_errno2("fclose", patch_script_path);
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
usage_unstage(void)
{
	fprintf(stderr, "usage: %s unstage [-p] [-F response-script] "
	    "[file-path ...]\n",
	    getprogname());
	exit(1);
}


static const struct got_error *
cmd_unstage(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *cwd = NULL;
	struct got_pathlist_head paths;
	struct got_pathlist_entry *pe;
	int ch, pflag = 0;
	struct got_update_progress_arg upa;
	FILE *patch_script_file = NULL;
	const char *patch_script_path = NULL;
	struct choose_patch_arg cpa;

	TAILQ_INIT(&paths);

	while ((ch = getopt(argc, argv, "pF:")) != -1) {
		switch (ch) {
		case 'p':
			pflag = 1;
			break;
		case 'F':
			patch_script_path = optarg;
			break;
		default:
			usage_unstage();
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
	if (patch_script_path && !pflag)
		errx(1, "-F option can only be used together with -p option");

	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_worktree_open(&worktree, cwd);
	if (error) {
		if (error->code == GOT_ERR_NOT_WORKTREE)
			error = wrap_not_worktree_error(error, "unstage", cwd);
		goto done;
	}

	error = got_repo_open(&repo, got_worktree_get_repo_path(worktree),
	    NULL);
	if (error != NULL)
		goto done;

	if (patch_script_path) {
		patch_script_file = fopen(patch_script_path, "r");
		if (patch_script_file == NULL) {
			error = got_error_from_errno2("fopen",
			    patch_script_path);
			goto done;
		}
	}

	error = apply_unveil(got_repo_get_path(repo), 0,
	    got_worktree_get_root_path(worktree));
	if (error)
		goto done;

	error = get_worktree_paths_from_argv(&paths, argc, argv, worktree);
	if (error)
		goto done;

	cpa.patch_script_file = patch_script_file;
	cpa.action = "unstage";
	memset(&upa, 0, sizeof(upa));
	error = got_worktree_unstage(worktree, &paths, update_progress,
	    &upa, pflag ? choose_patch : NULL, &cpa, repo);
	if (!error)
		print_update_progress_stats(&upa);
done:
	if (patch_script_file && fclose(patch_script_file) == EOF &&
	    error == NULL)
		error = got_error_from_errno2("fclose", patch_script_path);
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
usage_cat(void)
{
	fprintf(stderr, "usage: %s cat [-r repository ] [ -c commit ] [ -P ] "
	    "arg1 [arg2 ...]\n", getprogname());
	exit(1);
}

static const struct got_error *
cat_blob(struct got_object_id *id, struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err;
	struct got_blob_object *blob;

	err = got_object_open_as_blob(&blob, repo, id, 8192);
	if (err)
		return err;

	err = got_object_blob_dump_to_file(NULL, NULL, NULL, outfile, blob);
	got_object_blob_close(blob);
	return err;
}

static const struct got_error *
cat_tree(struct got_object_id *id, struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err;
	struct got_tree_object *tree;
	int nentries, i;

	err = got_object_open_as_tree(&tree, repo, id);
	if (err)
		return err;

	nentries = got_object_tree_get_nentries(tree);
	for (i = 0; i < nentries; i++) {
		struct got_tree_entry *te;
		char *id_str;
		if (sigint_received || sigpipe_received)
			break;
		te = got_object_tree_get_entry(tree, i);
		err = got_object_id_str(&id_str, got_tree_entry_get_id(te));
		if (err)
			break;
		fprintf(outfile, "%s %.7o %s\n", id_str,
		    got_tree_entry_get_mode(te),
		    got_tree_entry_get_name(te));
		free(id_str);
	}

	got_object_tree_close(tree);
	return err;
}

static const struct got_error *
cat_commit(struct got_object_id *id, struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err;
	struct got_commit_object *commit;
	const struct got_object_id_queue *parent_ids;
	struct got_object_qid *pid;
	char *id_str = NULL;
	const char *logmsg = NULL;

	err = got_object_open_as_commit(&commit, repo, id);
	if (err)
		return err;

	err = got_object_id_str(&id_str, got_object_commit_get_tree_id(commit));
	if (err)
		goto done;

	fprintf(outfile, "%s%s\n", GOT_COMMIT_LABEL_TREE, id_str);
	parent_ids = got_object_commit_get_parent_ids(commit);
	fprintf(outfile, "numparents %d\n",
	    got_object_commit_get_nparents(commit));
	SIMPLEQ_FOREACH(pid, parent_ids, entry) {
		char *pid_str;
		err = got_object_id_str(&pid_str, pid->id);
		if (err)
			goto done;
		fprintf(outfile, "%s%s\n", GOT_COMMIT_LABEL_PARENT, pid_str);
		free(pid_str);
	}
	fprintf(outfile, "%s%s %lld +0000\n", GOT_COMMIT_LABEL_AUTHOR,
	    got_object_commit_get_author(commit),
	    (long long)got_object_commit_get_author_time(commit));

	fprintf(outfile, "%s%s %lld +0000\n", GOT_COMMIT_LABEL_COMMITTER,
	    got_object_commit_get_author(commit),
	    (long long)got_object_commit_get_committer_time(commit));

	logmsg = got_object_commit_get_logmsg_raw(commit);
	fprintf(outfile, "messagelen %zd\n", strlen(logmsg));
	fprintf(outfile, "%s", logmsg);
done:
	free(id_str);
	got_object_commit_close(commit);
	return err;
}

static const struct got_error *
cat_tag(struct got_object_id *id, struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err;
	struct got_tag_object *tag;
	char *id_str = NULL;
	const char *tagmsg = NULL;

	err = got_object_open_as_tag(&tag, repo, id);
	if (err)
		return err;

	err = got_object_id_str(&id_str, got_object_tag_get_object_id(tag));
	if (err)
		goto done;

	fprintf(outfile, "%s%s\n", GOT_TAG_LABEL_OBJECT, id_str);

	switch (got_object_tag_get_object_type(tag)) {
	case GOT_OBJ_TYPE_BLOB:
		fprintf(outfile, "%s%s\n", GOT_TAG_LABEL_TYPE,
		    GOT_OBJ_LABEL_BLOB);
		break;
	case GOT_OBJ_TYPE_TREE:
		fprintf(outfile, "%s%s\n", GOT_TAG_LABEL_TYPE,
		    GOT_OBJ_LABEL_TREE);
		break;
	case GOT_OBJ_TYPE_COMMIT:
		fprintf(outfile, "%s%s\n", GOT_TAG_LABEL_TYPE,
		    GOT_OBJ_LABEL_COMMIT);
		break;
	case GOT_OBJ_TYPE_TAG:
		fprintf(outfile, "%s%s\n", GOT_TAG_LABEL_TYPE,
		    GOT_OBJ_LABEL_TAG);
		break;
	default:
		break;
	}

	fprintf(outfile, "%s%s\n", GOT_TAG_LABEL_TAG,
	    got_object_tag_get_name(tag));

	fprintf(outfile, "%s%s %lld +0000\n", GOT_TAG_LABEL_TAGGER,
	    got_object_tag_get_tagger(tag),
	    (long long)got_object_tag_get_tagger_time(tag));

	tagmsg = got_object_tag_get_message(tag);
	fprintf(outfile, "messagelen %zd\n", strlen(tagmsg));
	fprintf(outfile, "%s", tagmsg);
done:
	free(id_str);
	got_object_tag_close(tag);
	return err;
}

static const struct got_error *
cmd_cat(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	struct got_worktree *worktree = NULL;
	char *cwd = NULL, *repo_path = NULL, *label = NULL;
	const char *commit_id_str = NULL;
	struct got_object_id *id = NULL, *commit_id = NULL;
	int ch, obj_type, i, force_path = 0;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "c:r:P")) != -1) {
		switch (ch) {
		case 'c':
			commit_id_str = optarg;
			break;
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				return got_error_from_errno2("realpath",
				    optarg);
			got_path_strip_trailing_slashes(repo_path);
			break;
		case 'P':
			force_path = 1;
			break;
		default:
			usage_cat();
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
	if (worktree) {
		if (repo_path == NULL) {
			repo_path = strdup(
			    got_worktree_get_repo_path(worktree));
			if (repo_path == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		}
	}

	if (repo_path == NULL) {
		repo_path = getcwd(NULL, 0);
		if (repo_path == NULL)
			return got_error_from_errno("getcwd");
	}

	error = got_repo_open(&repo, repo_path, NULL);
	free(repo_path);
	if (error != NULL)
		goto done;

	error = apply_unveil(got_repo_get_path(repo), 1, NULL);
	if (error)
		goto done;

	if (commit_id_str == NULL)
		commit_id_str = GOT_REF_HEAD;
	error = got_repo_match_object_id(&commit_id, NULL,
	    commit_id_str, GOT_OBJ_TYPE_COMMIT, 1, repo);
	if (error)
		goto done;

	for (i = 0; i < argc; i++) {
		if (force_path) {
			error = got_object_id_by_path(&id, repo, commit_id,
			    argv[i]);
			if (error)
				break;
		} else {
			error = got_repo_match_object_id(&id, &label, argv[i],
			    GOT_OBJ_TYPE_ANY, 0, repo);
			if (error) {
				if (error->code != GOT_ERR_BAD_OBJ_ID_STR &&
				    error->code != GOT_ERR_NOT_REF)
					break;
				error = got_object_id_by_path(&id, repo,
				    commit_id, argv[i]);
				if (error)
					break;
			}
		}

		error = got_object_get_type(&obj_type, repo, id);
		if (error)
			break;

		switch (obj_type) {
		case GOT_OBJ_TYPE_BLOB:
			error = cat_blob(id, repo, stdout);
			break;
		case GOT_OBJ_TYPE_TREE:
			error = cat_tree(id, repo, stdout);
			break;
		case GOT_OBJ_TYPE_COMMIT:
			error = cat_commit(id, repo, stdout);
			break;
		case GOT_OBJ_TYPE_TAG:
			error = cat_tag(id, repo, stdout);
			break;
		default:
			error = got_error(GOT_ERR_OBJ_TYPE);
			break;
		}
		if (error)
			break;
		free(label);
		label = NULL;
		free(id);
		id = NULL;
	}
done:
	free(label);
	free(id);
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
usage_info(void)
{
	fprintf(stderr, "usage: %s info [path ...]\n",
	    getprogname());
	exit(1);
}

static const struct got_error *
print_path_info(void *arg, const char *path, mode_t mode, time_t mtime,
    struct got_object_id *blob_id, struct got_object_id *staged_blob_id,
    struct got_object_id *commit_id)
{
	const struct got_error *err = NULL;
	char *id_str = NULL;
	char datebuf[128];
	struct tm mytm, *tm;
	struct got_pathlist_head *paths = arg;
	struct got_pathlist_entry *pe;

	/*
	 * Clear error indication from any of the path arguments which
	 * would cause this file index entry to be displayed.
	 */
	TAILQ_FOREACH(pe, paths, entry) {
		if (got_path_cmp(path, pe->path, strlen(path),
		    pe->path_len) == 0 ||
		    got_path_is_child(path, pe->path, pe->path_len))
			pe->data = NULL; /* no error */
	}

	printf(GOT_COMMIT_SEP_STR);
	if (S_ISLNK(mode))
		printf("symlink: %s\n", path);
	else if (S_ISREG(mode)) {
		printf("file: %s\n", path);
		printf("mode: %o\n", mode & (S_IRWXU | S_IRWXG | S_IRWXO));
	} else if (S_ISDIR(mode))
		printf("directory: %s\n", path);
	else
		printf("something: %s\n", path);

	tm = localtime_r(&mtime, &mytm);
	if (tm == NULL)
		return NULL;
	if (strftime(datebuf, sizeof(datebuf), "%c %Z", tm) >= sizeof(datebuf))
		return got_error(GOT_ERR_NO_SPACE);
	printf("timestamp: %s\n", datebuf);

	if (blob_id) {
		err = got_object_id_str(&id_str, blob_id);
		if (err)
			return err;
		printf("based on blob: %s\n", id_str);
		free(id_str);
	}

	if (staged_blob_id) {
		err = got_object_id_str(&id_str, staged_blob_id);
		if (err)
			return err;
		printf("based on staged blob: %s\n", id_str);
		free(id_str);
	}

	if (commit_id) {
		err = got_object_id_str(&id_str, commit_id);
		if (err)
			return err;
		printf("based on commit: %s\n", id_str);
		free(id_str);
	}

	return NULL;
}

static const struct got_error *
cmd_info(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_worktree *worktree = NULL;
	char *cwd = NULL, *id_str = NULL;
	struct got_pathlist_head paths;
	struct got_pathlist_entry *pe;
	char *uuidstr = NULL;
	int ch, show_files = 0;

	TAILQ_INIT(&paths);

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			usage_info();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

#ifndef PROFILE
	if (pledge("stdio rpath wpath flock proc exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif
	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_worktree_open(&worktree, cwd);
	if (error) {
		if (error->code == GOT_ERR_NOT_WORKTREE)
			error = wrap_not_worktree_error(error, "status", cwd);
		goto done;
	}

	error = apply_unveil(NULL, 0, got_worktree_get_root_path(worktree));
	if (error)
		goto done;

	if (argc >= 1) {
		error = get_worktree_paths_from_argv(&paths, argc, argv,
		    worktree);
		if (error)
			goto done;
		show_files = 1;
	}

	error = got_object_id_str(&id_str,
	    got_worktree_get_base_commit_id(worktree));
	if (error)
		goto done;

	error = got_worktree_get_uuid(&uuidstr, worktree);
	if (error)
		goto done;

	printf("work tree: %s\n", got_worktree_get_root_path(worktree));
	printf("work tree base commit: %s\n", id_str);
	printf("work tree path prefix: %s\n",
	    got_worktree_get_path_prefix(worktree));
	printf("work tree branch reference: %s\n",
	    got_worktree_get_head_ref_name(worktree));
	printf("work tree UUID: %s\n", uuidstr);
	printf("repository: %s\n", got_worktree_get_repo_path(worktree));

	if (show_files) {
		struct got_pathlist_entry *pe;
		TAILQ_FOREACH(pe, &paths, entry) {
			if (pe->path_len == 0)
				continue;
			/*
			 * Assume this path will fail. This will be corrected
			 * in print_path_info() in case the path does suceeed.
			 */
			pe->data = (void *)got_error_path(pe->path,
			    GOT_ERR_BAD_PATH);
		}
		error = got_worktree_path_info(worktree, &paths,
		    print_path_info, &paths, check_cancelled, NULL);
		if (error)
			goto done;
		TAILQ_FOREACH(pe, &paths, entry) {
			if (pe->data != NULL) {
				error = pe->data; /* bad path */
				break;
			}
		}
	}
done:
	TAILQ_FOREACH(pe, &paths, entry)
		free((char *)pe->path);
	got_pathlist_free(&paths);
	free(cwd);
	free(id_str);
	free(uuidstr);
	return error;
}
