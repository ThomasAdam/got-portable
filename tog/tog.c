/*
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

#include <curses.h>
#include <panel.h>
#include <locale.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <err.h>
#include <unistd.h>

#include "got_error.h"
#include "got_object.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_diff.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

enum tog_view_id {
	TOG_VIEW_LOG,
	TOG_VIEW_DIFF,
	TOG_VIEW_BLAME,
};

struct tog_cmd {
	const char *name;
	const struct got_error *(*cmd_main)(int, char *[]);
	void (*cmd_usage)(void);
	enum tog_view_id view;
	const char *descr;
};

__dead void	usage(void);
__dead void	usage_log(void);
__dead void	usage_diff(void);
__dead void	usage_blame(void);

const struct got_error*	cmd_log(int, char *[]);
const struct got_error*	cmd_diff(int, char *[]);
const struct got_error*	cmd_blame(int, char *[]);

struct tog_cmd tog_commands[] = {
	{ "log",	cmd_log,	usage_log,	TOG_VIEW_LOG,
	    "show repository history" },
	{ "diff",	cmd_diff,	usage_diff,	TOG_VIEW_DIFF,
	    "compare files and directories" },
	{ "blame",	cmd_blame,	usage_blame,	TOG_VIEW_BLAME,
	    "show line-by-line file history" },
};

/* globals */
WINDOW *tog_main_win;
PANEL *tog_main_panel;
static struct tog_log_view {
	WINDOW *window;
	PANEL *panel;
} tog_log_view;

__dead void
usage_log(void)
{
	endwin();
	fprintf(stderr, "usage: %s log [-c commit] [repository-path]\n",
	    getprogname());
	exit(1);
}

static const struct got_error *
draw_commit(struct got_commit_object *commit, struct got_object_id *id)
{
	const struct got_error *err = NULL;
	char *logmsg0 = NULL, *logmsg = NULL;
	char *author0 = NULL, *author = NULL;
	char *newline, *smallerthan;
	char *line = NULL;
	char *id_str = NULL;
	size_t len;

	err = got_object_id_str(&id_str, id);
	if (err)
		return err;
	logmsg0 = strdup(commit->logmsg);
	if (logmsg0 == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	logmsg = logmsg0;
	while (*logmsg == '\n')
		logmsg++;
	newline = strchr(logmsg, '\n');
	if (newline)
		*newline = '\0';

	author0 = strdup(commit->author);
	if (author0 == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	author = author0;
	smallerthan = strchr(author, '<');
	if (smallerthan)
		*smallerthan = '\0';
	else {
		char *at = strchr(author, '@');
		if (at)
			*at = '\0';
	}

	if (asprintf(&line, "%.8s %.20s %s", id_str, author, logmsg) == -1) {
		err = got_error_from_errno();
		goto done;
	}

	waddstr(tog_log_view.window, line);
	len = strlen(line);
	while (len < COLS - 1) {
		waddch(tog_log_view.window, ' ');
		len++;
	}
	waddch(tog_log_view.window, '\n');
done:
	free(logmsg0);
	free(author0);
	free(line);
	free(id_str);
	return err;
}
struct commit_queue_entry {
	TAILQ_ENTRY(commit_queue_entry) entry;
	struct got_object_id *id;
	struct got_commit_object *commit;
};
TAILQ_HEAD(commit_queue, commit_queue_entry);

static const struct got_error *
fetch_commits(struct commit_queue *commits, struct got_object *root_obj,
    struct got_object_id *root_id, struct got_repository *repo, int limit)
{
	const struct got_error *err;
	struct got_commit_object *root_commit;
	struct commit_queue_entry *entry;
	int ncommits = 0;

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
	TAILQ_INSERT_HEAD(commits, entry, entry);

	while (entry->commit->nparents > 0 && ncommits < limit) {
		struct got_parent_id *pid;
		struct got_object *obj;
		struct got_commit_object *pcommit;
		struct commit_queue_entry *pentry;

		entry = TAILQ_LAST(commits, commit_queue);

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
		TAILQ_INSERT_TAIL(commits, pentry, entry);
		ncommits++;
	}

	return err;
}

static void
free_commits(struct commit_queue *commits)
{
	struct commit_queue_entry *entry;

	while (!TAILQ_EMPTY(commits)) {
		entry = TAILQ_FIRST(commits);
		TAILQ_REMOVE(commits, entry, entry);
		got_object_commit_close(entry->commit);
		free(entry->id);
		free(entry);
	}
}

static const struct got_error *
draw_commits(struct commit_queue *commits, int selected)
{
	const struct got_error *err = NULL;
	struct commit_queue_entry *entry;
	int ncommits = 0;

	wclear(tog_log_view.window);

	TAILQ_FOREACH(entry, commits, entry) {
		if (ncommits == selected)
			wstandout(tog_log_view.window);
		err = draw_commit(entry->commit, entry->id);
		if (ncommits == selected)
			wstandend(tog_log_view.window);
		if (err)
			break;
		ncommits++;
	}

	update_panels();
	doupdate();

	return err;
}

static const struct got_error *
show_log_view(struct got_object_id *start_id, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object *obj;
	int ch, done = 0, selected = 0, refetch_commits = 1;
	struct got_object_id *id = start_id;
	struct commit_queue commits;

	if (tog_log_view.window == NULL) {
		tog_log_view.window = newwin(0, 0, 0, 0);
		if (tog_log_view.window == NULL)
			return got_error_from_errno();
		keypad(tog_log_view.window, TRUE);
	}
	if (tog_log_view.panel == NULL) {
		tog_log_view.panel = new_panel(tog_log_view.window);
		if (tog_log_view.panel == NULL)
			return got_error_from_errno();
	}

	err = got_object_open(&obj, repo, id);
	if (err)
		return err;
	if (got_object_get_type(obj) != GOT_OBJ_TYPE_COMMIT) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	TAILQ_INIT(&commits);
	do {
		if (refetch_commits) {
			free_commits(&commits);
			err = fetch_commits(&commits, obj, id, repo, LINES);
			if (err)
				return err;
			refetch_commits = 0;
		}

		err = draw_commits(&commits, selected);
		if (err)
			return err;

		nodelay(stdscr, FALSE);
		ch = wgetch(tog_log_view.window);
		switch (ch) {
			case 'q':
				done = 1;
				break;
			case 'k':
			case KEY_UP:
				if (selected > 0)
					selected--;
				break;
			case 'j':
			case KEY_DOWN:
				if (selected < LINES - 1)
					selected++;
				break;
			default:
				break;
		}
		nodelay(stdscr, TRUE);
	} while (!done);
done:
	free_commits(&commits);
	got_object_close(obj);
	return err;
}

const struct got_error *
cmd_log(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo;
	struct got_object_id *id = NULL;
	char *repo_path = NULL;
	char *start_commit = NULL;
	int ch;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc tty", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "c:")) != -1) {
		switch (ch) {
		case 'c':
			start_commit = optarg;
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
	} else {
		struct got_object *obj;
		error = got_object_open_by_id_str(&obj, repo, start_commit);
		if (error == NULL) {
			id = got_object_get_id(obj);
			if (id == NULL)
				error = got_error_from_errno();
		}
	}
	if (error != NULL)
		return error;
	error = show_log_view(id, repo);
	free(id);
	got_repo_close(repo);
	return error;
}

__dead void
usage_diff(void)
{
	endwin();
	fprintf(stderr, "usage: %s diff [repository-path] object1 object2\n",
	    getprogname());
	exit(1);
}

const struct got_error *
cmd_diff(int argc, char *argv[])
{
	return got_error(GOT_ERR_NOT_IMPL);
}

__dead void
usage_blame(void)
{
	endwin();
	fprintf(stderr, "usage: %s blame [repository-path] blob-object\n",
	    getprogname());
	exit(1);
}

const struct got_error *
cmd_blame(int argc, char *argv[])
{
	return got_error(GOT_ERR_NOT_IMPL);
}

static const struct got_error *
init_curses(void)
{
	initscr();
	cbreak();
	noecho();
	nonl();
	intrflush(stdscr, FALSE);
	keypad(stdscr, TRUE);

	tog_main_win = newwin(0, 0, 0, 0);
	if (tog_main_win == NULL)
		return got_error_from_errno();
	tog_main_panel = new_panel(tog_main_win);
	if (tog_main_panel == NULL)
		return got_error_from_errno();

	return NULL;
}

__dead void
usage(void)
{
	int i;

	fprintf(stderr, "usage: %s [-h] [command] [arg ...]\n\n"
	    "Available commands:\n", getprogname());
	for (i = 0; i < nitems(tog_commands); i++) {
		struct tog_cmd *cmd = &tog_commands[i];
		fprintf(stderr, "    %s: %s\n", cmd->name, cmd->descr);
	}
	exit(1);
}

static char **
make_argv(const char *arg0, const char *arg1)
{
	char **argv;
	int argc = (arg1 == NULL ? 1 : 2);

	argv = calloc(argc, sizeof(char *));
	if (argv == NULL)
		err(1, "calloc");
	argv[0] = strdup(arg0);
	if (argv[0] == NULL)
		err(1, "calloc");
	if (arg1) {
		argv[1] = strdup(arg1);
		if (argv[1] == NULL)
			err(1, "calloc");
	}

	return argv;
}

int
main(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct tog_cmd *cmd = NULL;
	int ch, hflag = 0;
	char **cmd_argv = NULL;

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
	optreset = 1;

	if (argc == 0) {
		/* Build an argument vector which runs a default command. */
		cmd = &tog_commands[0];
		cmd_argv = make_argv(cmd->name, NULL);
		argc = 1;
	} else {
		int i;

		/* Did the user specific a command? */
		for (i = 0; i < nitems(tog_commands); i++) {
			if (strncmp(tog_commands[i].name, argv[0],
			    strlen(argv[0])) == 0) {
				cmd = &tog_commands[i];
				if (hflag)
					tog_commands[i].cmd_usage();
				break;
			}
		}
		if (cmd == NULL) {
			/* Did the user specify a repository? */
			char *repo_path = realpath(argv[0], NULL);
			if (repo_path) {
				struct got_repository *repo;
				error = got_repo_open(&repo, repo_path);
				if (error == NULL)
					got_repo_close(repo);
			} else
				error = got_error_from_errno();
			if (error) {
				fprintf(stderr, "%s: '%s' is neither a known "
				    "command nor a path to a repository\n",
				    getprogname(), argv[0]);
				free(repo_path);
				return 1;
			}
			cmd = &tog_commands[0];
			cmd_argv = make_argv(cmd->name, repo_path);
			argc = 2;
			free(repo_path);
		}
	}

	error = init_curses();
	if (error) {
		fprintf(stderr, "cannot initialize ncurses: %s\n", error->msg);
		return 1;
	}

	error = cmd->cmd_main(argc, cmd_argv ? cmd_argv : argv);
	if (error)
		goto done;
done:
	endwin();
	free(cmd_argv);
	if (error)
		fprintf(stderr, "%s: %s\n", getprogname(), error->msg);
	return 0;
}
