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

#include <curses.h>
#include <panel.h>
#include <locale.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <err.h>

#include "got_error.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

enum tog_view_id {
	TOG_VIEW_LOG,
	TOG_VIEW_DIFF,
	TOG_VIEW_BLAME,
};

struct tog_cmd {
	const char *cmd_name;
	const struct got_error *(*cmd_main)(int, char *[]);
	void (*cmd_usage)(void);
	enum tog_view_id view;
	const char *cmd_descr;
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
enum tog_view_id tog_view_id;
WINDOW *tog_main_win;
PANEL *tog_main_panel;

__dead void
usage_log(void)
{
	fprintf(stderr, "usage: %s log [repository-path]\n",
	    getprogname());
	exit(1);
}

const struct got_error *
cmd_log(int argc, char *argv[])
{
	return got_error(GOT_ERR_NOT_IMPL);
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
	return got_error(GOT_ERR_NOT_IMPL);
}

__dead void
usage_blame(void)
{
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

	fprintf(stderr, "usage: %s [-h] command [arg ...]\n\n"
	    "Available commands:\n", getprogname());
	for (i = 0; i < nitems(tog_commands); i++) {
		struct tog_cmd *cmd = &tog_commands[i];
		fprintf(stderr, "    %s: %s\n", cmd->cmd_name, cmd->cmd_descr);
	}
	exit(1);
}

int
main(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct tog_cmd *cmd = NULL;
	int ch, hflag = 0;

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

	if (argc == 0)
		cmd = &tog_commands[0];
	else {
		int i;

		for (i = 0; i < nitems(tog_commands); i++) {
			if (strncmp(tog_commands[i].cmd_name, argv[0],
			    strlen(argv[0])) == 0) {
				cmd = &tog_commands[i];
				if (hflag)
					tog_commands[i].cmd_usage();
				break;
			}
		}
		if (cmd == NULL) {
			fprintf(stderr, "%s: unknown command '%s'\n",
			    getprogname(), argv[0]);
			return 1;
		}
	}

	error = init_curses();
	if (error) {
		fprintf(stderr, "Cannot initialize ncurses: %s\n", error->msg);
		return 1;
	}

	error = cmd->cmd_main(argc, argv);
	if (error)
		goto done;
done:
	endwin();
	if (error)
		fprintf(stderr, "%s: %s\n", getprogname(), error->msg);
	return 0;
}
