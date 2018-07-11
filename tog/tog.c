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
#include <sys/stat.h>

#include <errno.h>
#define _XOPEN_SOURCE_EXTENDED
#include <curses.h>
#undef _XOPEN_SOURCE_EXTENDED
#include <panel.h>
#include <locale.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <util.h>
#include <limits.h>
#include <wchar.h>
#include <time.h>
#include <pthread.h>

#include "got_error.h"
#include "got_object.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_diff.h"
#include "got_opentemp.h"
#include "got_commit_graph.h"
#include "got_utf8.h"
#include "got_blame.h"

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

struct tog_cmd {
	const char *name;
	const struct got_error *(*cmd_main)(int, char *[]);
	void (*cmd_usage)(void);
	const char *descr;
};

__dead static void	usage(void);
__dead static void	usage_log(void);
__dead static void	usage_diff(void);
__dead static void	usage_blame(void);
__dead static void	usage_tree(void);

static const struct got_error*	cmd_log(int, char *[]);
static const struct got_error*	cmd_diff(int, char *[]);
static const struct got_error*	cmd_blame(int, char *[]);
static const struct got_error*	cmd_tree(int, char *[]);

static struct tog_cmd tog_commands[] = {
	{ "log",	cmd_log,	usage_log,
	    "show repository history" },
	{ "diff",	cmd_diff,	usage_diff,
	    "compare files and directories" },
	{ "blame",	cmd_blame,	usage_blame,
	    "show line-by-line file history" },
	{ "tree",	cmd_tree,	usage_tree,
	    "browse trees in repository" },
};

static struct tog_view {
	WINDOW *window;
	PANEL *panel;
} tog_log_view, tog_diff_view, tog_blame_view, tog_tree_view;

static const struct got_error *
show_diff_view(struct got_object *, struct got_object *,
    struct got_repository *);
static const struct got_error *
show_log_view(struct got_object_id *, struct got_repository *);
static const struct got_error *
show_blame_view(const char *, struct got_object_id *, struct got_repository *);
static const struct got_error *
show_tree_view(struct got_tree_object *, struct got_object_id *,
    struct got_repository *);

__dead static void
usage_log(void)
{
	endwin();
	fprintf(stderr, "usage: %s log [-c commit] [repository-path]\n",
	    getprogname());
	exit(1);
}

/* Create newly allocated wide-character string equivalent to a byte string. */
static const struct got_error *
mbs2ws(wchar_t **ws, size_t *wlen, const char *s)
{
	char *vis = NULL;
	const struct got_error *err = NULL;

	*ws = NULL;
	*wlen = mbstowcs(NULL, s, 0);
	if (*wlen == (size_t)-1) {
		int vislen;
		if (errno != EILSEQ)
			return got_error_from_errno();

		/* byte string invalid in current encoding; try to "fix" it */
		err = got_mbsavis(&vis, &vislen, s);
		if (err)
			return err;
		*wlen = mbstowcs(NULL, vis, 0);
		if (*wlen == (size_t)-1) {
			err = got_error_from_errno(); /* give up */
			goto done;
		}
	}

	*ws = calloc(*wlen + 1, sizeof(*ws));
	if (*ws == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	if (mbstowcs(*ws, vis ? vis : s, *wlen) != *wlen)
		err = got_error_from_errno();
done:
	free(vis);
	if (err) {
		free(*ws);
		*ws = NULL;
		*wlen = 0;
	}
	return err;
}

/* Format a line for display, ensuring that it won't overflow a width limit. */
static const struct got_error *
format_line(wchar_t **wlinep, int *widthp, const char *line, int wlimit)
{
	const struct got_error *err = NULL;
	int cols = 0;
	wchar_t *wline = NULL;
	size_t wlen;
	int i;

	*wlinep = NULL;
	*widthp = 0;

	err = mbs2ws(&wline, &wlen, line);
	if (err)
		return err;

	i = 0;
	while (i < wlen && cols < wlimit) {
		int width = wcwidth(wline[i]);
		switch (width) {
		case 0:
			i++;
			break;
		case 1:
		case 2:
			if (cols + width <= wlimit) {
				cols += width;
				i++;
			}
			break;
		case -1:
			if (wline[i] == L'\t')
				cols += TABSIZE - ((cols + 1) % TABSIZE);
			i++;
			break;
		default:
			err = got_error_from_errno();
			goto done;
		}
	}
	wline[i] = L'\0';
	if (widthp)
		*widthp = cols;
done:
	if (err)
		free(wline);
	else
		*wlinep = wline;
	return err;
}

static const struct got_error *
draw_commit(struct got_commit_object *commit, struct got_object_id *id)
{
	const struct got_error *err = NULL;
	char datebuf[10]; /* YY-MM-DD + SPACE + NUL */
	char *logmsg0 = NULL, *logmsg = NULL;
	char *author0 = NULL, *author = NULL;
	wchar_t *wlogmsg = NULL, *wauthor = NULL;
	int author_width, logmsg_width;
	char *newline, *smallerthan;
	char *line = NULL;
	int col, limit;
	static const size_t date_display_cols = 9;
	static const size_t author_display_cols = 16;
	const int avail = COLS;

	if (strftime(datebuf, sizeof(datebuf), "%g/%m/%d ", &commit->tm_committer)
	    >= sizeof(datebuf))
		return got_error(GOT_ERR_NO_SPACE);

	if (avail < date_display_cols)
		limit = MIN(sizeof(datebuf) - 1, avail);
	else
		limit = MIN(date_display_cols, sizeof(datebuf) - 1);
	waddnstr(tog_log_view.window, datebuf, limit);
	col = limit + 1;
	if (col > avail)
		goto done;

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
	limit = avail - col;
	err = format_line(&wauthor, &author_width, author, limit);
	if (err)
		goto done;
	waddwstr(tog_log_view.window, wauthor);
	col += author_width;
	while (col <= avail && author_width < author_display_cols + 1) {
		waddch(tog_log_view.window, ' ');
		col++;
		author_width++;
	}
	if (col > avail)
		goto done;

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
	limit = avail - col;
	err = format_line(&wlogmsg, &logmsg_width, logmsg, limit);
	if (err)
		goto done;
	waddwstr(tog_log_view.window, wlogmsg);
	col += logmsg_width;
	while (col <= avail) {
		waddch(tog_log_view.window, ' ');
		col++;
	}
done:
	free(logmsg0);
	free(wlogmsg);
	free(author0);
	free(wauthor);
	free(line);
	return err;
}

struct commit_queue_entry {
	TAILQ_ENTRY(commit_queue_entry) entry;
	struct got_object_id *id;
	struct got_commit_object *commit;
};
TAILQ_HEAD(commit_queue, commit_queue_entry);

static struct commit_queue_entry *
alloc_commit_queue_entry(struct got_commit_object *commit,
    struct got_object_id *id)
{
	struct commit_queue_entry *entry;

	entry = calloc(1, sizeof(*entry));
	if (entry == NULL)
		return NULL;

	entry->id = id;
	entry->commit = commit;
	return entry;
}

static void
pop_commit(struct commit_queue *commits)
{
	struct commit_queue_entry *entry;

	entry = TAILQ_FIRST(commits);
	TAILQ_REMOVE(commits, entry, entry);
	got_object_commit_close(entry->commit);
	/* Don't free entry->id! It is owned by the commit graph. */
	free(entry);
}

static void
free_commits(struct commit_queue *commits)
{
	while (!TAILQ_EMPTY(commits))
		pop_commit(commits);
}

static const struct got_error *
queue_commits(struct got_commit_graph *graph, struct commit_queue *commits,
    struct got_object_id *start_id, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object_id *id;
	struct commit_queue_entry *entry;

	err = got_commit_graph_iter_start(graph, start_id);
	if (err)
		return err;

	entry = TAILQ_LAST(commits, commit_queue);
	if (entry && got_object_id_cmp(entry->id, start_id) == 0) {
		int nfetched;

		/* Start ID's commit is already on the queue; skip over it. */
		err = got_commit_graph_iter_next(&id, graph);
		if (err && err->code != GOT_ERR_ITER_NEED_MORE)
			return err;

		err = got_commit_graph_fetch_commits(&nfetched, graph, 1, repo);
		if (err)
			return err;
	}

	while (1) {
		struct got_commit_object *commit;

		err = got_commit_graph_iter_next(&id, graph);
		if (err) {
			if (err->code == GOT_ERR_ITER_NEED_MORE)
				err = NULL;
			break;
		}

		err = got_object_open_as_commit(&commit, repo, id);
		if (err)
			break;

		entry = alloc_commit_queue_entry(commit, id);
		if (entry == NULL) {
			err = got_error_from_errno();
			break;
		}

		TAILQ_INSERT_TAIL(commits, entry, entry);
	}

	return err;
}

static const struct got_error *
fetch_next_commit(struct commit_queue_entry **pentry,
    struct commit_queue_entry *entry, struct commit_queue *commits,
    struct got_commit_graph *graph, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object_qid *qid;

	*pentry = NULL;

	/* Populate commit graph with entry's parent commits. */
	SIMPLEQ_FOREACH(qid, &entry->commit->parent_ids, entry) {
		int nfetched;
		err = got_commit_graph_fetch_commits_up_to(&nfetched,
			graph, qid->id, repo);
		if (err)
			return err;
	}

	/* Append outstanding commits to queue in graph sort order. */
	err = queue_commits(graph, commits, entry->id, repo);
	if (err) {
		if (err->code == GOT_ERR_ITER_COMPLETED)
			err = NULL;
		return err;
	}

	/* Next entry to display should now be available. */
	*pentry = TAILQ_NEXT(entry, entry);
	if (*pentry == NULL)
		return got_error(GOT_ERR_NO_OBJ);

	return NULL;
}

static const struct got_error *
get_head_commit_id(struct got_object_id **head_id, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_reference *head_ref;

	*head_id = NULL;

	err = got_ref_open(&head_ref, repo, GOT_REF_HEAD);
	if (err)
		return err;

	err = got_ref_resolve(head_id, repo, head_ref);
	got_ref_close(head_ref);
	if (err) {
		*head_id = NULL;
		return err;
	}

	return NULL;
}

static const struct got_error *
draw_commits(struct commit_queue_entry **last, struct commit_queue_entry **selected,
    struct commit_queue_entry *first, int selected_idx, int limit)
{
	const struct got_error *err = NULL;
	struct commit_queue_entry *entry;
	int ncommits;
	char *id_str, *header;
	size_t header_len;

	entry = first;
	*selected = NULL;
	ncommits = 0;
	while (entry) {
		if (++ncommits - 1 == selected_idx) {
			*selected = entry;
			break;
		}
		entry = TAILQ_NEXT(entry, entry);
	}
	if (*selected == NULL)
		return got_error(GOT_ERR_RANGE);

	err = got_object_id_str(&id_str, (*selected)->id);
	if (err)
		return err;

	if (asprintf(&header, "commit: %s", id_str) == -1) {
		err = got_error_from_errno();
		free(id_str);
		return err;
	}

	werase(tog_log_view.window);

	header_len = strlen(header);
	if (header_len > COLS) {
		id_str[COLS + 1] = '\0';
		header_len = COLS;
	}
	wprintw(tog_log_view.window, header);
	while (header_len < COLS) {
		waddch(tog_log_view.window, ' ');
		header_len++;
	}
	free(id_str);
	free(header);

	entry = first;
	*last = first;
	ncommits = 0;
	while (entry) {
		if (ncommits == limit - 1)
			break;
		if (ncommits == selected_idx) {
			wstandout(tog_log_view.window);
			*selected = entry;
		}
		err = draw_commit(entry->commit, entry->id);
		if (ncommits == selected_idx)
			wstandend(tog_log_view.window);
		if (err)
			break;
		ncommits++;
		*last = entry;
		entry = TAILQ_NEXT(entry, entry);
	}

	update_panels();
	doupdate();

	return err;
}

static void
scroll_up(struct commit_queue_entry **first_displayed_entry, int maxscroll,
    struct commit_queue *commits)
{
	struct commit_queue_entry *entry;
	int nscrolled = 0;

	entry = TAILQ_FIRST(commits);
	if (*first_displayed_entry == entry)
		return;

	entry = *first_displayed_entry;
	while (entry && nscrolled < maxscroll) {
		entry = TAILQ_PREV(entry, commit_queue, entry);
		if (entry) {
			*first_displayed_entry = entry;
			nscrolled++;
		}
	}
}

static const struct got_error *
scroll_down(struct commit_queue_entry **first_displayed_entry, int maxscroll,
    struct commit_queue_entry *last_displayed_entry,
    struct commit_queue *commits, struct got_commit_graph *graph,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct commit_queue_entry *pentry;
	int nscrolled = 0;

	do {
		pentry = TAILQ_NEXT(last_displayed_entry, entry);
		if (pentry == NULL) {
			err = fetch_next_commit(&pentry, last_displayed_entry,
			    commits, graph, repo);
			if (err || pentry == NULL)
				break;
		}
		last_displayed_entry = pentry;

		pentry = TAILQ_NEXT(*first_displayed_entry, entry);
		if (pentry == NULL)
			break;
		*first_displayed_entry = pentry;
	} while (++nscrolled < maxscroll);

	return err;
}

static int
num_parents(struct commit_queue_entry *entry)
{
	int nparents = 0;

	while (entry) {
		entry = TAILQ_NEXT(entry, entry);
		nparents++;
	}

	return nparents;
}

static const struct got_error *
show_commit(struct commit_queue_entry *entry, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_object *obj1 = NULL, *obj2 = NULL;
	struct got_object_qid *parent_id;

	err = got_object_open(&obj2, repo, entry->id);
	if (err)
		return err;

	parent_id = SIMPLEQ_FIRST(&entry->commit->parent_ids);
	if (parent_id) {
		err = got_object_open(&obj1, repo, parent_id->id);
		if (err)
			goto done;
	}

	err = show_diff_view(obj1, obj2, repo);
done:
	if (obj1)
		got_object_close(obj1);
	if (obj2)
		got_object_close(obj2);
	return err;
}

static const struct got_error *
browse_commit(struct commit_queue_entry *entry, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_tree_object *tree;

	err = got_object_open_as_tree(&tree, repo, entry->commit->tree_id);
	if (err)
		return err;

	err = show_tree_view(tree, entry->id, repo);
	got_object_tree_close(tree);
	return err;
}

static const struct got_error *
show_log_view(struct got_object_id *start_id, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object_id *head_id = NULL;
	int ch, done = 0, selected = 0, nparents, nfetched;
	struct got_commit_graph *graph;
	struct commit_queue commits;
	struct commit_queue_entry *entry = NULL;
	struct commit_queue_entry *first_displayed_entry = NULL;
	struct commit_queue_entry *last_displayed_entry = NULL;
	struct commit_queue_entry *selected_entry = NULL;

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
	} else
		show_panel(tog_log_view.panel);

	err = get_head_commit_id(&head_id, repo);
	if (err)
		return err;

	TAILQ_INIT(&commits);

	err = got_commit_graph_open(&graph, head_id, 0, repo);
	if (err)
		goto done;

	/* Populate commit graph with a sufficient number of commits. */
	err = got_commit_graph_fetch_commits_up_to(&nfetched, graph, start_id,
	    repo);
	if (err)
		goto done;
	err = got_commit_graph_fetch_commits(&nfetched, graph, LINES, repo);
	if (err)
		goto done;

	/*
	 * Open the initial batch of commits, sorted in commit graph order.
	 * We keep all commits open throughout the lifetime of the log view
	 * in order to avoid having to re-fetch commits from disk while
	 * updating the display.
	 */
	err = queue_commits(graph, &commits, head_id, repo);
	if (err && err->code != GOT_ERR_ITER_COMPLETED)
		goto done;

	/* Find entry corresponding to the first commit to display. */
	TAILQ_FOREACH(entry, &commits, entry) {
		if (got_object_id_cmp(entry->id, start_id) == 0) {
			first_displayed_entry = entry;
			break;
		}
	}
	if (first_displayed_entry == NULL) {
		err = got_error(GOT_ERR_NO_OBJ);
		goto done;
	}

	selected_entry = first_displayed_entry;
	while (!done) {
		err = draw_commits(&last_displayed_entry, &selected_entry,
		    first_displayed_entry, selected, LINES);
		if (err)
			goto done;

		nodelay(stdscr, FALSE);
		ch = wgetch(tog_log_view.window);
		nodelay(stdscr, TRUE);
		switch (ch) {
			case ERR:
				if (errno) {
					err = got_error_from_errno();
					goto done;
				}
				break;
			case 'q':
				done = 1;
				break;
			case 'k':
			case KEY_UP:
				if (selected > 0)
					selected--;
				if (selected > 0)
					break;
				scroll_up(&first_displayed_entry, 1, &commits);
				break;
			case KEY_PPAGE:
				if (TAILQ_FIRST(&commits) ==
				    first_displayed_entry) {
					selected = 0;
					break;
				}
				scroll_up(&first_displayed_entry, LINES,
				    &commits);
				break;
			case 'j':
			case KEY_DOWN:
				nparents = num_parents(first_displayed_entry);
				if (selected < LINES - 2 &&
				    selected < nparents - 1) {
					selected++;
					break;
				}
				err = scroll_down(&first_displayed_entry, 1,
				    last_displayed_entry, &commits, graph,
				    repo);
				if (err)
					goto done;
				break;
			case KEY_NPAGE:
				err = scroll_down(&first_displayed_entry, LINES,
				    last_displayed_entry, &commits, graph,
				    repo);
				if (err)
					goto done;
				if (last_displayed_entry->commit->nparents > 0)
					break;
				/* can't scroll any further; move cursor down */
				nparents = num_parents(first_displayed_entry);
				if (selected < LINES - 2 ||
				    selected < nparents - 1)
					selected = MIN(LINES - 2, nparents - 1);
				break;
			case KEY_RESIZE:
				if (selected > LINES - 1)
					selected = LINES - 2;
				break;
			case KEY_ENTER:
			case '\r':
				err = show_commit(selected_entry, repo);
				if (err)
					goto done;
				show_panel(tog_log_view.panel);
				break;
			case 't':
				err = browse_commit(selected_entry, repo);
				if (err)
					goto done;
				show_panel(tog_log_view.panel);
				break;
			default:
				break;
		}
	}
done:
	free(head_id);
	if (graph)
		got_commit_graph_close(graph);
	free_commits(&commits);
	return err;
}

static const struct got_error *
cmd_log(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo;
	struct got_object_id *start_id = NULL;
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
		error = get_head_commit_id(&start_id, repo);
		if (error != NULL)
			return error;
	} else {
		struct got_object *obj;
		error = got_object_open_by_id_str(&obj, repo, start_commit);
		if (error == NULL) {
			start_id = got_object_get_id(obj);
			if (start_id == NULL)
				error = got_error_from_errno();
		}
	}
	if (error != NULL)
		return error;
	error = show_log_view(start_id, repo);
	free(start_id);
	got_repo_close(repo);
	return error;
}

__dead static void
usage_diff(void)
{
	endwin();
	fprintf(stderr, "usage: %s diff [repository-path] object1 object2\n",
	    getprogname());
	exit(1);
}

static char *
parse_next_line(FILE *f, size_t *len)
{
	char *line;
	size_t linelen;
	size_t lineno;
	const char delim[3] = { '\0', '\0', '\0'};

	line = fparseln(f, &linelen, &lineno, delim, 0);
	if (len)
		*len = linelen;
	return line;
}

static const struct got_error *
draw_file(WINDOW *window, FILE *f, int *first_displayed_line,
    int *last_displayed_line, int *eof, int max_lines)
{
	const struct got_error *err;
	int nlines = 0, nprinted = 0;
	char *line;
	size_t len;
	wchar_t *wline;
	int width;

	rewind(f);
	werase(window);

	*eof = 0;
	while (nprinted < max_lines) {
		line = parse_next_line(f, &len);
		if (line == NULL) {
			*eof = 1;
			break;
		}
		if (++nlines < *first_displayed_line) {
			free(line);
			continue;
		}

		err = format_line(&wline, &width, line, COLS);
		if (err) {
			free(line);
			return err;
		}
		waddwstr(window, wline);
		if (width < COLS)
			waddch(window, '\n');
		if (++nprinted == 1)
			*first_displayed_line = nlines;
		free(line);
	}
	*last_displayed_line = nlines;

	update_panels();
	doupdate();

	return NULL;
}

static const struct got_error *
show_diff_view(struct got_object *obj1, struct got_object *obj2,
    struct got_repository *repo)
{
	const struct got_error *err;
	FILE *f;
	int ch, done = 0, first_displayed_line = 1, last_displayed_line = LINES;
	int eof, i;

	if (obj1 != NULL && obj2 != NULL &&
	    got_object_get_type(obj1) != got_object_get_type(obj2))
		return got_error(GOT_ERR_OBJ_TYPE);

	f = got_opentemp();
	if (f == NULL)
		return got_error_from_errno();

	switch (got_object_get_type(obj1 ? obj1 : obj2)) {
	case GOT_OBJ_TYPE_BLOB:
		err = got_diff_objects_as_blobs(obj1, obj2, repo, f);
		break;
	case GOT_OBJ_TYPE_TREE:
		err = got_diff_objects_as_trees(obj1, obj2, repo, f);
		break;
	case GOT_OBJ_TYPE_COMMIT:
		err = got_diff_objects_as_commits(obj1, obj2, repo, f);
		break;
	default:
		return got_error(GOT_ERR_OBJ_TYPE);
	}

	fflush(f);

	if (tog_diff_view.window == NULL) {
		tog_diff_view.window = newwin(0, 0, 0, 0);
		if (tog_diff_view.window == NULL)
			return got_error_from_errno();
		keypad(tog_diff_view.window, TRUE);
	}
	if (tog_diff_view.panel == NULL) {
		tog_diff_view.panel = new_panel(tog_diff_view.window);
		if (tog_diff_view.panel == NULL)
			return got_error_from_errno();
	} else
		show_panel(tog_diff_view.panel);

	while (!done) {
		err = draw_file(tog_diff_view.window, f, &first_displayed_line,
		    &last_displayed_line, &eof, LINES);
		if (err)
			break;
		nodelay(stdscr, FALSE);
		ch = wgetch(tog_diff_view.window);
		nodelay(stdscr, TRUE);
		switch (ch) {
			case 'q':
				done = 1;
				break;
			case 'k':
			case KEY_UP:
			case KEY_BACKSPACE:
				if (first_displayed_line > 1)
					first_displayed_line--;
				break;
			case KEY_PPAGE:
				i = 0;
				while (i++ < LINES - 1 &&
				    first_displayed_line > 1)
					first_displayed_line--;
				break;
			case 'j':
			case KEY_DOWN:
			case KEY_ENTER:
			case '\r':
				if (!eof)
					first_displayed_line++;
				break;
			case KEY_NPAGE:
			case ' ':
				i = 0;
				while (!eof && i++ < LINES - 1) {
					char *line = parse_next_line(f, NULL);
					first_displayed_line++;
					if (line == NULL)
						break;
				}
				break;
			default:
				break;
		}
	}
	fclose(f);
	return err;
}

static const struct got_error *
cmd_diff(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_object *obj1 = NULL, *obj2 = NULL;
	char *repo_path = NULL;
	char *obj_id_str1 = NULL, *obj_id_str2 = NULL;
	int ch;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc tty", NULL) == -1)
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
	if (error)
		goto done;

	error = got_object_open_by_id_str(&obj1, repo, obj_id_str1);
	if (error)
		goto done;

	error = got_object_open_by_id_str(&obj2, repo, obj_id_str2);
	if (error)
		goto done;

	error = show_diff_view(obj1, obj2, repo);
done:
	got_repo_close(repo);
	if (obj1)
		got_object_close(obj1);
	if (obj2)
		got_object_close(obj2);
	return error;
}

__dead static void
usage_blame(void)
{
	endwin();
	fprintf(stderr, "usage: %s blame [-c commit] [repository-path] path\n",
	    getprogname());
	exit(1);
}

struct tog_blame_line {
	int annotated;
	struct got_object_id *id;
};

static const struct got_error *
draw_blame(WINDOW *window, FILE *f, const char *path,
    struct tog_blame_line *lines, int nlines, int blame_complete,
    int selected_line, int *first_displayed_line, int *last_displayed_line,
    int *eof, int max_lines)
{
	const struct got_error *err;
	int lineno = 0, nprinted = 0;
	char *line;
	size_t len;
	wchar_t *wline;
	int width, wlimit;
	struct tog_blame_line *blame_line;
	struct got_object_id *prev_id = NULL;

	rewind(f);
	werase(window);

	if (asprintf(&line, "[%d-%d/%d] annotation of %s%s",
	    *first_displayed_line, *last_displayed_line, nlines,
	    path, blame_complete ? "" : " in progress...") == -1)
		return got_error_from_errno();
	err = format_line(&wline, &width, line, COLS);
	free(line);
	if (err)
		return err;
	waddwstr(window, wline);
	if (width < COLS)
		waddch(window, '\n');

	*eof = 0;
	while (nprinted < max_lines - 1) {
		line = parse_next_line(f, &len);
		if (line == NULL) {
			*eof = 1;
			break;
		}
		if (++lineno < *first_displayed_line) {
			free(line);
			continue;
		}

		wlimit = COLS < 9 ? 0 : COLS - 9;
		err = format_line(&wline, &width, line, wlimit);
		if (err) {
			free(line);
			return err;
		}

		if (nprinted == selected_line - 1)
			wstandout(window);

		blame_line = &lines[lineno - 1];
		if (blame_line->annotated && prev_id &&
		    got_object_id_cmp(prev_id, blame_line->id) == 0)
			waddstr(window, "         ");
		else if (blame_line->annotated) {
			char *id_str;
			err = got_object_id_str(&id_str, blame_line->id);
			if (err) {
				free(line);
				return err;
			}
			wprintw(window, "%.8s ", id_str);
			free(id_str);
			prev_id = blame_line->id;
		} else {
			waddstr(window, "........ ");
			prev_id = NULL;
		}

		waddwstr(window, wline);
		while (width < wlimit) {
			waddch(window, ' '); /* width == wlimit - 1 ? '\n' : ' '); */
			width++;
		}
		if (nprinted == selected_line - 1)
			wstandend(window);
		if (++nprinted == 1)
			*first_displayed_line = lineno;
		free(line);
	}
	*last_displayed_line = lineno;

	update_panels();
	doupdate();

	return NULL;
}

struct tog_blame_cb_args {
	pthread_mutex_t *mutex;
	struct tog_blame_line *lines; /* one per line */
	int nlines;

	FILE *f;
	const char *path;
	WINDOW *window;
	int *first_displayed_line;
	int *last_displayed_line;
	int *selected_line;
	int *quit;
};

static const struct got_error *
blame_cb(void *arg, int nlines, int lineno, struct got_object_id *id)
{
	const struct got_error *err = NULL;
	struct tog_blame_cb_args *a = arg;
	struct tog_blame_line *line;
	int eof;

	if (nlines != a->nlines ||
	    (lineno != -1 && lineno < 1) || lineno > a->nlines)
		return got_error(GOT_ERR_RANGE);

	if (pthread_mutex_lock(a->mutex) != 0)
		return got_error_from_errno();

	if (*a->quit) {	/* user has quit the blame view */
		err = got_error(GOT_ERR_ITER_COMPLETED);
		goto done;
	}

	if (lineno == -1)
		goto done; /* no change in this commit */

	line = &a->lines[lineno - 1];
	if (line->annotated)
		goto done;

	line->id = got_object_id_dup(id);
	if (line->id == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	line->annotated = 1;

	err = draw_blame(a->window, a->f, a->path, a->lines, a->nlines, 0,
	     *a->selected_line, a->first_displayed_line, a->last_displayed_line,
	    &eof, LINES);
done:
	if (pthread_mutex_unlock(a->mutex) != 0)
		return got_error_from_errno();
	return err;
}

struct tog_blame_thread_args {
	const char *path;
	struct got_object_id *commit_id;
	struct got_repository *repo;
	void *blame_cb_args;
	int *complete;
};

static void *
blame_thread(void *arg)
{
	const struct got_error *err;
	struct tog_blame_thread_args *ta = arg;
	struct tog_blame_cb_args *a = ta->blame_cb_args;
	int eof;

	err = got_blame_incremental(ta->path, ta->commit_id, ta->repo,
	    blame_cb, ta->blame_cb_args);
	*ta->complete = 1;
	if (err)
		return (void *)err;

	if (pthread_mutex_lock(a->mutex) != 0)
		return (void *)got_error_from_errno();

	err = draw_blame(a->window, a->f, a->path, a->lines, a->nlines, 1,
	    *a->selected_line, a->first_displayed_line, a->last_displayed_line,
	    &eof, LINES);

	if (pthread_mutex_unlock(a->mutex) != 0 && err == NULL)
		err = got_error_from_errno();

	return (void *)err;
}


static const struct got_error *
open_blamed_commit_and_parent(struct got_object **pobj, struct got_object **obj,
    struct tog_blame_line *lines, int first_displayed_line,
    int selected_line, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct tog_blame_line *line;
	struct got_commit_object *commit = NULL;
	struct got_object_qid *pid;

	*pobj = NULL;
	*obj = NULL;

	line = &lines[first_displayed_line - 1 + selected_line - 1];
	if (!line->annotated || line->id == NULL)
		return NULL;

	err = got_object_open(obj, repo, line->id);
	if (err)
		goto done;

	err = got_object_commit_open(&commit, repo, *obj);
	if (err)
		goto done;

	pid = SIMPLEQ_FIRST(&commit->parent_ids);
	if (pid) {
		err = got_object_open(pobj, repo, pid->id);
		if (err)
			goto done;
	}
done:
	if (commit)
		got_object_commit_close(commit);
	return err;
}

static const struct got_error *
show_blame_view(const char *path, struct got_object_id *commit_id,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	int ch, done = 0, first_displayed_line = 1, last_displayed_line = LINES;
	int selected_line = first_displayed_line;
	int eof, i, blame_complete = 0;
	struct got_object *obj = NULL, *pobj = NULL;
	struct got_blob_object *blob = NULL;
	FILE *f = NULL;
	size_t filesize, nlines = 0;
	struct tog_blame_line *lines = NULL;
	pthread_t thread = NULL;
	pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	struct tog_blame_cb_args blame_cb_args;
	struct tog_blame_thread_args blame_thread_args;
	struct got_repository *blame_thread_repo = NULL;

	err = got_object_open_by_path(&obj, repo, commit_id, path);
	if (err)
		goto done;
	if (got_object_get_type(obj) != GOT_OBJ_TYPE_BLOB) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = got_object_blob_open(&blob, repo, obj, 8192);
	if (err)
		goto done;
	f = got_opentemp();
	if (f == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	err = got_object_blob_dump_to_file(&filesize, &nlines, f, blob);
	if (err)
		goto done;

	lines = calloc(nlines, sizeof(*lines));
	if (lines == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	err = got_repo_open(&blame_thread_repo, got_repo_get_path(repo));
	if (err)
		goto done;

	if (tog_blame_view.window == NULL) {
		tog_blame_view.window = newwin(0, 0, 0, 0);
		if (tog_blame_view.window == NULL)
			return got_error_from_errno();
		keypad(tog_blame_view.window, TRUE);
	}
	if (tog_blame_view.panel == NULL) {
		tog_blame_view.panel = new_panel(tog_blame_view.window);
		if (tog_blame_view.panel == NULL)
			return got_error_from_errno();
	} else
		show_panel(tog_blame_view.panel);

	if (pthread_mutex_init(&mutex, NULL) != 0) {
		err = got_error_from_errno();
		goto done;
	}
	blame_cb_args.lines = lines;
	blame_cb_args.nlines = nlines;
	blame_cb_args.mutex = &mutex;
	blame_cb_args.f = f;
	blame_cb_args.path = path;
	blame_cb_args.window = tog_blame_view.window;
	blame_cb_args.first_displayed_line = &first_displayed_line;
	blame_cb_args.selected_line = &selected_line;
	blame_cb_args.last_displayed_line = &last_displayed_line;
	blame_cb_args.quit = &done;

	blame_thread_args.path = path;
	blame_thread_args.commit_id = commit_id;
	blame_thread_args.repo = blame_thread_repo;
	blame_thread_args.blame_cb_args = &blame_cb_args;
	blame_thread_args.complete = &blame_complete;

	if (pthread_create(&thread, NULL, blame_thread,
	    &blame_thread_args) != 0) {
		err = got_error_from_errno();
		goto done;
	}

	while (!done) {
		if (pthread_mutex_lock(&mutex) != 0) {
			err = got_error_from_errno();
			goto done;
		}
		err = draw_blame(tog_blame_view.window, f, path, lines, nlines,
		    blame_complete, selected_line, &first_displayed_line,
		    &last_displayed_line, &eof, LINES);
		if (pthread_mutex_unlock(&mutex) != 0) {
			err = got_error_from_errno();
			goto done;
		}
		if (err)
			break;
		nodelay(stdscr, FALSE);
		ch = wgetch(tog_blame_view.window);
		nodelay(stdscr, TRUE);
		if (pthread_mutex_lock(&mutex) != 0) {
			err = got_error_from_errno();
			goto done;
		}
		switch (ch) {
			case 'q':
				done = 1;
				break;
			case 'k':
			case KEY_UP:
				if (selected_line > 1)
					selected_line--;
				else if (selected_line == 1 &&
				    first_displayed_line > 1)
					first_displayed_line--;
				break;
			case KEY_PPAGE:
				if (first_displayed_line == 1) {
					selected_line = 1;
					break;
				}
				if (first_displayed_line > LINES - 1)
					first_displayed_line -= (LINES - 1);
				else
					first_displayed_line = 1;
				break;
			case 'j':
			case KEY_DOWN:
				if (selected_line < LINES - 1)
					selected_line++;
				else if (last_displayed_line < nlines)
					first_displayed_line++;
				break;
			case KEY_ENTER:
			case '\r':
				err = open_blamed_commit_and_parent(&pobj, &obj,
				    lines, first_displayed_line, selected_line,
				    repo);
				if (err)
					goto done;
				if (pobj == NULL && obj == NULL)
					break;
				err = show_diff_view(pobj, obj, repo);
				if (pobj) {
					got_object_close(pobj);
					pobj = NULL;
				}
				got_object_close(obj);
				obj = NULL;
				show_panel(tog_blame_view.panel);
				if (err)
					goto done;
				break;
			case KEY_NPAGE:
			case ' ':
				if (last_displayed_line >= nlines &&
				    selected_line < LINES - 1) {
					selected_line = LINES - 1;
					break;
				}
				if (last_displayed_line + LINES - 1 <= nlines)
					first_displayed_line += LINES - 1;
				else
					first_displayed_line =
					    nlines - (LINES - 2);
				break;
			default:
				break;
		}
		if (pthread_mutex_unlock(&mutex) != 0) {
			err = got_error_from_errno();
			goto done;
		}
	}
done:
	if (thread) {
		if (pthread_join(thread, (void **)&err) != 0)
			err = got_error_from_errno();
		if (err && err->code == GOT_ERR_ITER_COMPLETED)
			err = NULL;
	}
	if (blame_thread_repo)
		got_repo_close(blame_thread_repo);
	if (blob)
		got_object_blob_close(blob);
	if (pobj)
		got_object_close(pobj);
	if (obj)
		got_object_close(obj);
	if (f)
		fclose(f);
	for (i = 0; i < nlines; i++)
		free(lines[i].id);
	free(lines);
	return err;
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
	if (pledge("stdio rpath wpath cpath flock proc tty", NULL) == -1)
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
		return error;

	if (commit_id_str == NULL) {
		struct got_reference *head_ref;
		error = got_ref_open(&head_ref, repo, GOT_REF_HEAD);
		if (error != NULL)
			goto done;
		error = got_ref_resolve(&commit_id, repo, head_ref);
		got_ref_close(head_ref);
	} else {
		struct got_object *obj;
		error = got_object_open_by_id_str(&obj, repo, commit_id_str);
		if (error != NULL)
			goto done;
		commit_id = got_object_get_id(obj);
		if (commit_id == NULL)
			error = got_error_from_errno();
		got_object_close(obj);
	}
	if (error != NULL)
		goto done;

	error = show_blame_view(path, commit_id, repo);
done:
	free(commit_id);
	if (repo)
		got_repo_close(repo);
	return error;
}

static const struct got_error *
draw_tree_entries(struct got_tree_entry **first_displayed_entry,
    struct got_tree_entry **last_displayed_entry,
    struct got_tree_entry **selected_entry, int *ndisplayed,
    WINDOW *window, const char *label, const char *parent_path,
    const struct got_tree_entries *entries, int selected, int limit, int isroot)
{
	const struct got_error *err = NULL;
	struct got_tree_entry *te;
	wchar_t *wline;
	int width, n;

	*ndisplayed = 0;

	werase(window);

	if (limit == 0)
		return NULL;

	err = format_line(&wline, &width, label, COLS);
	if (err)
		return err;
	waddwstr(window, wline);
	if (width < COLS)
		waddch(window, '\n');
	if (--limit <= 0)
		return NULL;
	err = format_line(&wline, &width, parent_path, COLS);
	if (err)
		return err;
	waddwstr(window, wline);
	if (width < COLS)
		waddch(window, '\n');
	if (--limit <= 0)
		return NULL;
	waddch(window, '\n');
	if (--limit <= 0)
		return NULL;

	te = SIMPLEQ_FIRST(&entries->head);
	if (*first_displayed_entry == NULL) {
		if (selected == 0) {
			wstandout(window);
			*selected_entry = NULL;
		}
		waddstr(window, "  ..\n");	/* parent directory */
		if (selected == 0)
			wstandend(window);
		(*ndisplayed)++;
		if (--limit <= 0)
			return NULL;
		n = 1;
	} else {
		n = 0;
		while (te != *first_displayed_entry)
			te = SIMPLEQ_NEXT(te, entry);
	}

	while (te) {
		char *line = NULL;
		if (asprintf(&line, "  %s%s",
		    te->name, S_ISDIR(te->mode) ? "/" : "") == -1)
			return got_error_from_errno();
		err = format_line(&wline, &width, line, COLS);
		if (err) {
			free(line);
			break;
		}
		if (n == selected) {
			wstandout(window);
			*selected_entry = te;
		}
		waddwstr(window, wline);
		if (width < COLS)
			waddch(window, '\n');
		if (n == selected)
			wstandend(window);
		free(line);
		n++;
		(*ndisplayed)++;
		*last_displayed_entry = te;
		if (--limit <= 0)
			break;
		te = SIMPLEQ_NEXT(te, entry);
	}

	return err;
}

static void
tree_scroll_up(struct got_tree_entry **first_displayed_entry, int maxscroll,
    const struct got_tree_entries *entries, int isroot)
{
	struct got_tree_entry *te, *prev;
	int i;

	if (*first_displayed_entry == NULL)
		return;

	te = SIMPLEQ_FIRST(&entries->head);
	if (*first_displayed_entry == te) {
		if (!isroot)
			*first_displayed_entry = NULL;
		return;
	}

	/* XXX this is stupid... switch to TAILQ? */
	for (i = 0; i < maxscroll; i++) {
		while (te != *first_displayed_entry) {
			prev = te;
			te = SIMPLEQ_NEXT(te, entry);
		}
		*first_displayed_entry = prev;
		te = SIMPLEQ_FIRST(&entries->head);
	}
	if (!isroot && te == SIMPLEQ_FIRST(&entries->head) && i < maxscroll)
		*first_displayed_entry = NULL;
}

static void
tree_scroll_down(struct got_tree_entry **first_displayed_entry, int maxscroll,
	struct got_tree_entry *last_displayed_entry,
	const struct got_tree_entries *entries)
{
	struct got_tree_entry *next;
	int n = 0;

	if (SIMPLEQ_NEXT(last_displayed_entry, entry) == NULL)
		return;

	if (*first_displayed_entry)
		next = SIMPLEQ_NEXT(*first_displayed_entry, entry);
	else
		next = SIMPLEQ_FIRST(&entries->head);
	while (next) {
		*first_displayed_entry = next;
		if (++n >= maxscroll)
			break;
		next = SIMPLEQ_NEXT(next, entry);
	}
}

struct tog_parent_tree {
	TAILQ_ENTRY(tog_parent_tree) entry;
	struct got_tree_object *tree;
	struct got_tree_entry *first_displayed_entry;
	struct got_tree_entry *selected_entry;
	int selected;
};

TAILQ_HEAD(tog_parent_trees, tog_parent_tree);

static const struct got_error *
tree_entry_path(char **path, struct tog_parent_trees *parents,
    struct got_tree_entry *te)
{
	const struct got_error *err = NULL;
	struct tog_parent_tree *pt;
	size_t len = 2; /* for leading slash and NUL */

	TAILQ_FOREACH(pt, parents, entry)
		len += strlen(pt->selected_entry->name) + 1 /* slash */;
	if (te)
		len += strlen(te->name);

	*path = calloc(1, len);
	if (path == NULL)
		return got_error_from_errno();

	(*path)[0] = '/';
	pt = TAILQ_LAST(parents, tog_parent_trees);
	while (pt) {
		if (strlcat(*path, pt->selected_entry->name, len) >= len) {
			err = got_error(GOT_ERR_NO_SPACE);
			goto done;
		}
		if (strlcat(*path, "/", len) >= len) {
			err = got_error(GOT_ERR_NO_SPACE);
			goto done;
		}
		pt = TAILQ_PREV(pt, tog_parent_trees, entry);
	}
	if (te) {
		if (strlcat(*path, te->name, len) >= len) {
			err = got_error(GOT_ERR_NO_SPACE);
			goto done;
		}
	}
done:
	if (err) {
		free(*path);
		*path = NULL;
	}
	return err;
}

static const struct got_error *
blame_tree_entry(struct got_tree_entry *te, struct tog_parent_trees *parents,
    struct got_object_id *commit_id, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *path;
	
	err = tree_entry_path(&path, parents, te);
	if (err)
		return err;

	err = show_blame_view(path, commit_id, repo);
	free(path);
	return err;
}

static const struct got_error *
show_tree_view(struct got_tree_object *root, struct got_object_id *commit_id,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	int ch, done = 0, selected = 0;
	struct got_tree_object *tree = root;
	const struct got_tree_entries *entries;
	struct got_tree_entry *first_displayed_entry = NULL;
	struct got_tree_entry *last_displayed_entry = NULL;
	struct got_tree_entry *selected_entry = NULL;
	char *commit_id_str = NULL, *tree_label = NULL;
	int nentries, ndisplayed;
	struct tog_parent_trees parents;

	TAILQ_INIT(&parents);

	err = got_object_id_str(&commit_id_str, commit_id);
	if (err != NULL)
		goto done;

	if (asprintf(&tree_label, "tree of commit %s", commit_id_str) == -1) {
		err = got_error_from_errno();
		goto done;
	}

	if (tog_tree_view.window == NULL) {
		tog_tree_view.window = newwin(0, 0, 0, 0);
		if (tog_tree_view.window == NULL)
			return got_error_from_errno();
		keypad(tog_tree_view.window, TRUE);
	}
	if (tog_tree_view.panel == NULL) {
		tog_tree_view.panel = new_panel(tog_tree_view.window);
		if (tog_tree_view.panel == NULL)
			return got_error_from_errno();
	} else
		show_panel(tog_tree_view.panel);

	entries = got_object_tree_get_entries(root);
	first_displayed_entry = SIMPLEQ_FIRST(&entries->head);
	while (!done) {
		char *parent_path;
		entries = got_object_tree_get_entries(tree);
		nentries = entries->nentries;
		if (tree != root)
			nentries++; /* '..' directory */

		err = tree_entry_path(&parent_path, &parents, NULL);
		if (err)
			goto done;

		err = draw_tree_entries(&first_displayed_entry,
		    &last_displayed_entry, &selected_entry, &ndisplayed,
		    tog_tree_view.window, tree_label, parent_path, entries,
		    selected, LINES, tree == root);
		free(parent_path);
		if (err)
			break;

		nodelay(stdscr, FALSE);
		ch = wgetch(tog_tree_view.window);
		nodelay(stdscr, TRUE);
		switch (ch) {
			case 'q':
				done = 1;
				break;
			case 'k':
			case KEY_UP:
				if (selected > 0)
					selected--;
				if (selected > 0)
					break;
				tree_scroll_up(&first_displayed_entry, 1,
				    entries, tree == root);
				break;
			case KEY_PPAGE:
				if (SIMPLEQ_FIRST(&entries->head) ==
				    first_displayed_entry) {
					if (tree != root)
						first_displayed_entry = NULL;
					selected = 0;
					break;
				}
				tree_scroll_up(&first_displayed_entry, LINES,
				    entries, tree == root);
				break;
			case 'j':
			case KEY_DOWN:
				if (selected < ndisplayed - 1) {
					selected++;
					break;
				}
				tree_scroll_down(&first_displayed_entry, 1,
				    last_displayed_entry, entries);
				break;
			case KEY_NPAGE:
				tree_scroll_down(&first_displayed_entry, LINES,
				    last_displayed_entry, entries);
				if (SIMPLEQ_NEXT(last_displayed_entry, entry))
					break;
				/* can't scroll any further; move cursor down */
				if (selected < ndisplayed - 1)
					selected = ndisplayed - 1;
				break;
			case KEY_ENTER:
			case '\r':
				if (selected_entry == NULL) {
					struct tog_parent_tree *parent;
			case KEY_BACKSPACE:
					/* user selected '..' */
					if (tree == root)
						break;
					parent = TAILQ_FIRST(&parents);
					TAILQ_REMOVE(&parents, parent, entry);
					got_object_tree_close(tree);
					tree = parent->tree;
					first_displayed_entry =
					    parent->first_displayed_entry;
					selected_entry = parent->selected_entry;
					selected = parent->selected;
					free(parent);
				} else if (S_ISDIR(selected_entry->mode)) {
					struct tog_parent_tree *parent;
					struct got_tree_object *child;
					err = got_object_open_as_tree(
					    &child, repo, selected_entry->id);
					if (err)
						goto done;
					parent = calloc(1, sizeof(*parent));
					if (parent == NULL) {
						err = got_error_from_errno();
						goto done;
					}
					parent->tree = tree;
					parent->first_displayed_entry =
					   first_displayed_entry;
					parent->selected_entry = selected_entry;
					parent->selected = selected;
					TAILQ_INSERT_HEAD(&parents, parent,
					    entry);
					tree = child;
					selected = 0;
					first_displayed_entry = NULL;
				} else if (S_ISREG(selected_entry->mode)) {
					err = blame_tree_entry(selected_entry,
					    &parents, commit_id, repo);
					if (err)
						goto done;
				}
				break;
			case KEY_RESIZE:
				if (selected > LINES)
					selected = ndisplayed - 1;
				break;
			default:
				break;
		}
	}
done:
	free(tree_label);
	free(commit_id_str);
	while (!TAILQ_EMPTY(&parents)) {
		struct tog_parent_tree *parent;
		parent = TAILQ_FIRST(&parents);
		TAILQ_REMOVE(&parents, parent, entry);
		free(parent);

	}
	if (tree != root)
		got_object_tree_close(tree);
	return err;
}

__dead static void
usage_tree(void)
{
	endwin();
	fprintf(stderr, "usage: %s tree [-c commit] [repository-path]\n",
	    getprogname());
	exit(1);
}

static const struct got_error *
cmd_tree(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	char *repo_path = NULL;
	struct got_object_id *commit_id = NULL;
	char *commit_id_arg = NULL;
	struct got_commit_object *commit = NULL;
	struct got_tree_object *tree = NULL;
	int ch;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc tty", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "c:")) != -1) {
		switch (ch) {
		case 'c':
			commit_id_arg = optarg;
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

	if (commit_id_arg == NULL) {
		error = get_head_commit_id(&commit_id, repo);
		if (error != NULL)
			goto done;
	} else {
		struct got_object *obj;
		error = got_object_open_by_id_str(&obj, repo, commit_id_arg);
		if (error == NULL) {
			commit_id = got_object_get_id(obj);
			if (commit_id == NULL)
				error = got_error_from_errno();
		}
	}
	if (error != NULL)
		goto done;

	error = got_object_open_as_commit(&commit, repo, commit_id);
	if (error != NULL)
		goto done;

	error = got_object_open_as_tree(&tree, repo, commit->tree_id);
	if (error != NULL)
		goto done;

	error = show_tree_view(tree, commit_id, repo);
done:
	free(commit_id);
	if (commit)
		got_object_commit_close(commit);
	if (tree)
		got_object_tree_close(tree);
	if (repo)
		got_repo_close(repo);
	return error;
}
static void
init_curses(void)
{
	initscr();
	cbreak();
	noecho();
	nonl();
	intrflush(stdscr, FALSE);
	keypad(stdscr, TRUE);
	curs_set(0);
}

__dead static void
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
		if (hflag)
			usage();
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
				if (hflag) {
					fprintf(stderr, "%s: '%s' is not a "
					    "known command\n", getprogname(),
					    argv[0]);
					usage();
				}
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

	init_curses();

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
