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

#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

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
#include <libgen.h>

#include "got_error.h"
#include "got_object.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_diff.h"
#include "got_opentemp.h"
#include "got_commit_graph.h"
#include "got_utf8.h"
#include "got_blame.h"
#include "got_privsep.h"
#include "got_worktree.h"

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

#ifndef MAX
#define	MAX(_a,_b) ((_a) > (_b) ? (_a) : (_b))
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

enum tog_view_type {
	TOG_VIEW_DIFF,
	TOG_VIEW_LOG,
	TOG_VIEW_BLAME,
	TOG_VIEW_TREE
};

struct commit_queue_entry {
	TAILQ_ENTRY(commit_queue_entry) entry;
	struct got_object_id *id;
	struct got_commit_object *commit;
	int idx;
};
TAILQ_HEAD(commit_queue_head, commit_queue_entry);
struct commit_queue {
	int ncommits;
	struct commit_queue_head head;
};

struct tog_diff_view_state {
	struct got_object_id *id1, *id2;
	FILE *f;
	int first_displayed_line;
	int last_displayed_line;
	int eof;
	int diff_context;
	struct got_repository *repo;
	struct got_reflist_head *refs;

	/* passed from log view; may be NULL */
	struct tog_view *log_view;
};

pthread_mutex_t tog_mutex = PTHREAD_MUTEX_INITIALIZER;

struct tog_log_thread_args {
	pthread_cond_t need_commits;
	int commits_needed;
	struct got_commit_graph *graph;
	struct commit_queue *commits;
	const char *in_repo_path;
	struct got_object_id *start_id;
	struct got_repository *repo;
	int log_complete;
	sig_atomic_t *quit;
	struct tog_view *view;
	struct commit_queue_entry **first_displayed_entry;
	struct commit_queue_entry **selected_entry;
};

struct tog_log_view_state {
	struct commit_queue commits;
	struct commit_queue_entry *first_displayed_entry;
	struct commit_queue_entry *last_displayed_entry;
	struct commit_queue_entry *selected_entry;
	int selected;
	char *in_repo_path;
	struct got_repository *repo;
	struct got_reflist_head *refs;
	struct got_object_id *start_id;
	sig_atomic_t quit;
	pthread_t thread;
	struct tog_log_thread_args thread_args;
};

struct tog_blame_cb_args {
	struct tog_blame_line *lines; /* one per line */
	int nlines;

	struct tog_view *view;
	struct got_object_id *commit_id;
	int *quit;
};

struct tog_blame_thread_args {
	const char *path;
	struct got_repository *repo;
	struct tog_blame_cb_args *cb_args;
	int *complete;
};

struct tog_blame {
	FILE *f;
	size_t filesize;
	struct tog_blame_line *lines;
	int nlines;
	pthread_t thread;
	struct tog_blame_thread_args thread_args;
	struct tog_blame_cb_args cb_args;
	const char *path;
};

struct tog_blame_view_state {
	int first_displayed_line;
	int last_displayed_line;
	int selected_line;
	int blame_complete;
	int eof;
	int done;
	struct got_object_id_queue blamed_commits;
	struct got_object_qid *blamed_commit;
	char *path;
	struct got_repository *repo;
	struct got_reflist_head *refs;
	struct got_object_id *commit_id;
	struct tog_blame blame;
};

struct tog_parent_tree {
	TAILQ_ENTRY(tog_parent_tree) entry;
	struct got_tree_object *tree;
	struct got_tree_entry *first_displayed_entry;
	struct got_tree_entry *selected_entry;
	int selected;
};

TAILQ_HEAD(tog_parent_trees, tog_parent_tree);

struct tog_tree_view_state {
	char *tree_label;
	struct got_tree_object *root;
	struct got_tree_object *tree;
	const struct got_tree_entries *entries;
	struct got_tree_entry *first_displayed_entry;
	struct got_tree_entry *last_displayed_entry;
	struct got_tree_entry *selected_entry;
	int ndisplayed, selected, show_ids;
	struct tog_parent_trees parents;
	struct got_object_id *commit_id;
	struct got_repository *repo;
	struct got_reflist_head *refs;
};

/*
 * We implement two types of views: parent views and child views.
 *
 * The 'Tab' key switches between a parent view and its child view.
 * Child views are shown side-by-side to their parent view, provided
 * there is enough screen estate.
 *
 * When a new view is opened from within a parent view, this new view
 * becomes a child view of the parent view, replacing any existing child.
 *
 * When a new view is opened from within a child view, this new view
 * becomes a parent view which will obscure the views below until the
 * user quits the new parent view by typing 'q'.
 *
 * This list of views contains parent views only.
 * Child views are only pointed to by their parent view.
 */
TAILQ_HEAD(tog_view_list_head, tog_view);

struct tog_view {
	TAILQ_ENTRY(tog_view) entry;
	WINDOW *window;
	PANEL *panel;
	int nlines, ncols, begin_y, begin_x;
	int lines, cols; /* copies of LINES and COLS */
	int focussed;
	struct tog_view *parent;
	struct tog_view *child;
	int child_focussed;

	/* type-specific state */
	enum tog_view_type type;
	union {
		struct tog_diff_view_state diff;
		struct tog_log_view_state log;
		struct tog_blame_view_state blame;
		struct tog_tree_view_state tree;
	} state;

	const struct got_error *(*show)(struct tog_view *);
	const struct got_error *(*input)(struct tog_view **,
	    struct tog_view **, struct tog_view**, struct tog_view *, int);
	const struct got_error *(*close)(struct tog_view *);
};

static const struct got_error *open_diff_view(struct tog_view *,
    struct got_object_id *, struct got_object_id *, struct tog_view *,
    struct got_reflist_head *, struct got_repository *);
static const struct got_error *show_diff_view(struct tog_view *);
static const struct got_error *input_diff_view(struct tog_view **,
    struct tog_view **, struct tog_view **, struct tog_view *, int);
static const struct got_error* close_diff_view(struct tog_view *);

static const struct got_error *open_log_view(struct tog_view *,
    struct got_object_id *, struct got_reflist_head *,
    struct got_repository *, const char *, int);
static const struct got_error * show_log_view(struct tog_view *);
static const struct got_error *input_log_view(struct tog_view **,
    struct tog_view **, struct tog_view **, struct tog_view *, int);
static const struct got_error *close_log_view(struct tog_view *);

static const struct got_error *open_blame_view(struct tog_view *, char *,
    struct got_object_id *, struct got_reflist_head *, struct got_repository *);
static const struct got_error *show_blame_view(struct tog_view *);
static const struct got_error *input_blame_view(struct tog_view **,
    struct tog_view **, struct tog_view **, struct tog_view *, int);
static const struct got_error *close_blame_view(struct tog_view *);

static const struct got_error *open_tree_view(struct tog_view *,
    struct got_tree_object *, struct got_object_id *,
    struct got_reflist_head *, struct got_repository *);
static const struct got_error *show_tree_view(struct tog_view *);
static const struct got_error *input_tree_view(struct tog_view **,
    struct tog_view **, struct tog_view **, struct tog_view *, int);
static const struct got_error *close_tree_view(struct tog_view *);

static volatile sig_atomic_t tog_sigwinch_received;

static void
tog_sigwinch(int signo)
{
	tog_sigwinch_received = 1;
}

static const struct got_error *
view_close(struct tog_view *view)
{
	const struct got_error *err = NULL;

	if (view->child) {
		view_close(view->child);
		view->child = NULL;
	}
	if (view->close)
		err = view->close(view);
	if (view->panel)
		del_panel(view->panel);
	if (view->window)
		delwin(view->window);
	free(view);
	return err;
}

static struct tog_view *
view_open(int nlines, int ncols, int begin_y, int begin_x,
    enum tog_view_type type)
{
	struct tog_view *view = calloc(1, sizeof(*view));

	if (view == NULL)
		return NULL;

	view->type = type;
	view->lines = LINES;
	view->cols = COLS;
	view->nlines = nlines ? nlines : LINES - begin_y;
	view->ncols = ncols ? ncols : COLS - begin_x;
	view->begin_y = begin_y;
	view->begin_x = begin_x;
	view->window = newwin(nlines, ncols, begin_y, begin_x);
	if (view->window == NULL) {
		view_close(view);
		return NULL;
	}
	view->panel = new_panel(view->window);
	if (view->panel == NULL ||
	    set_panel_userptr(view->panel, view) != OK) {
		view_close(view);
		return NULL;
	}

	keypad(view->window, TRUE);
	return view;
}

static int
view_split_begin_x(int begin_x)
{
	if (begin_x > 0 || COLS < 120)
		return 0;
	return (COLS - MAX(COLS / 2, 80));
}

static const struct got_error *view_resize(struct tog_view *);

static const struct got_error *
view_splitscreen(struct tog_view *view)
{
	const struct got_error *err = NULL;

	view->begin_y = 0;
	view->begin_x = view_split_begin_x(0);
	view->nlines = LINES;
	view->ncols = COLS - view->begin_x;
	view->lines = LINES;
	view->cols = COLS;
	err = view_resize(view);
	if (err)
		return err;

	if (mvwin(view->window, view->begin_y, view->begin_x) == ERR)
		return got_error_from_errno();

	return NULL;
}

static const struct got_error *
view_fullscreen(struct tog_view *view)
{
	const struct got_error *err = NULL;

	view->begin_x = 0;
	view->begin_y = 0;
	view->nlines = LINES;
	view->ncols = COLS;
	view->lines = LINES;
	view->cols = COLS;
	err = view_resize(view);
	if (err)
		return err;

	if (mvwin(view->window, view->begin_y, view->begin_x) == ERR)
		return got_error_from_errno();

	return NULL;
}

static int
view_is_parent_view(struct tog_view *view)
{
	return view->parent == NULL;
}

static const struct got_error *
view_resize(struct tog_view *view)
{
	int nlines, ncols;

	if (view->lines > LINES)
		nlines = view->nlines - (view->lines - LINES);
	else
		nlines = view->nlines + (LINES - view->lines);

	if (view->cols > COLS)
		ncols = view->ncols - (view->cols - COLS);
	else
		ncols = view->ncols + (COLS - view->cols);

	if (wresize(view->window, nlines, ncols) == ERR)
		return got_error_from_errno();
	if (replace_panel(view->panel, view->window) == ERR)
		return got_error_from_errno();
	wclear(view->window);

	view->nlines = nlines;
	view->ncols = ncols;
	view->lines = LINES;
	view->cols = COLS;

	if (view->child) {
		view->child->begin_x = view_split_begin_x(view->begin_x);
		if (view->child->begin_x == 0) {
			view_fullscreen(view->child);
			if (view->child->focussed)
				show_panel(view->child->panel);
			else
				show_panel(view->panel);
		} else {
			view_splitscreen(view->child);
			show_panel(view->child->panel);
		}
	}

	return NULL;
}

static const struct got_error *
view_close_child(struct tog_view *view)
{
	const struct got_error *err = NULL;

	if (view->child == NULL)
		return NULL;

	err = view_close(view->child);
	view->child = NULL;
	return err;
}

static const struct got_error *
view_set_child(struct tog_view *view, struct tog_view *child)
{
	const struct got_error *err = NULL;

	view->child = child;
	child->parent = view;
	return err;
}

static int
view_is_splitscreen(struct tog_view *view)
{
	return !view_is_parent_view(view) && view->begin_x > 0;
}

static void
tog_resizeterm(void)
{
	int cols, lines;
	struct winsize size;

	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &size) < 0) {
		cols = 80;     /* Default */
		lines = 24;
	} else {
		cols = size.ws_col;
		lines = size.ws_row;
	}
	resize_term(lines, cols);
}

static const struct got_error *
view_input(struct tog_view **new, struct tog_view **dead,
    struct tog_view **focus, int *done, struct tog_view *view,
    struct tog_view_list_head *views)
{
	const struct got_error *err = NULL;
	struct tog_view *v;
	int ch, errcode;

	*new = NULL;
	*dead = NULL;
	*focus = NULL;

	nodelay(stdscr, FALSE);
	/* Allow threads to make progress while we are waiting for input. */
	errcode = pthread_mutex_unlock(&tog_mutex);
	if (errcode)
		return got_error_set_errno(errcode);
	ch = wgetch(view->window);
	errcode = pthread_mutex_lock(&tog_mutex);
	if (errcode)
		return got_error_set_errno(errcode);
	nodelay(stdscr, TRUE);

	if (tog_sigwinch_received) {
		tog_resizeterm();
		tog_sigwinch_received = 0;
		TAILQ_FOREACH(v, views, entry) {
			err = view_resize(v);
			if (err)
				return err;
			err = v->input(new, dead, focus, v, KEY_RESIZE);
			if (err)
				return err;
		}
	}

	switch (ch) {
		case ERR:
			break;
		case '\t':
			if (view->child) {
				*focus = view->child;
				view->child_focussed = 1;
			} else if (view->parent) {
				*focus = view->parent;
				view->parent->child_focussed = 0;
			}
			break;
		case 'q':
			err = view->input(new, dead, focus, view, ch);
			*dead = view;
			break;
		case 'Q':
			*done = 1;
			break;
		case 'f':
			if (view_is_parent_view(view)) {
				if (view->child == NULL)
					break;
				if (view_is_splitscreen(view->child)) {
					*focus = view->child;
					view->child_focussed = 1;
					err = view_fullscreen(view->child);
				} else
					err = view_splitscreen(view->child);
				if (err)
					break;
				err = view->child->input(new, dead, focus,
				    view->child, KEY_RESIZE);
			} else {
				if (view_is_splitscreen(view)) {
					*focus = view;
					view->parent->child_focussed = 1;
					err = view_fullscreen(view);
				} else {
					err = view_splitscreen(view);
				}
				if (err)
					break;
				err = view->input(new, dead, focus, view,
				    KEY_RESIZE);
			}
			break;
		case KEY_RESIZE:
			break;
		default:
			err = view->input(new, dead, focus, view, ch);
			break;
	}

	return err;
}

void
view_vborder(struct tog_view *view)
{
	PANEL *panel;
	struct tog_view *view_above;

	if (view->parent)
		return view_vborder(view->parent);

	panel = panel_above(view->panel);
	if (panel == NULL)
		return;

	view_above = panel_userptr(panel);
	mvwvline(view->window, view->begin_y, view_above->begin_x - 1,
	    got_locale_is_utf8() ? ACS_VLINE : '|', view->nlines);
}

int
view_needs_focus_indication(struct tog_view *view)
{
	if (view_is_parent_view(view)) {
		if (view->child == NULL || view->child_focussed)
			return 0;
		if (!view_is_splitscreen(view->child))
			return 0;
	} else if (!view_is_splitscreen(view))
		return 0;

	return view->focussed;
}

static const struct got_error *
view_loop(struct tog_view *view)
{
	const struct got_error *err = NULL;
	struct tog_view_list_head views;
	struct tog_view *new_view, *dead_view, *focus_view, *main_view;
	int fast_refresh = 10;
	int done = 0, errcode;

	errcode = pthread_mutex_lock(&tog_mutex);
	if (errcode)
		return got_error_set_errno(errcode);

	TAILQ_INIT(&views);
	TAILQ_INSERT_HEAD(&views, view, entry);

	main_view = view;
	view->focussed = 1;
	err = view->show(view);
	if (err)
		return err;
	update_panels();
	doupdate();
	while (!TAILQ_EMPTY(&views) && !done) {
		/* Refresh fast during initialization, then become slower. */
		if (fast_refresh && fast_refresh-- == 0)
			halfdelay(10); /* switch to once per second */

		err = view_input(&new_view, &dead_view, &focus_view, &done,
		    view, &views);
		if (err)
			break;
		if (dead_view) {
			struct tog_view *prev = NULL;

			if (view_is_parent_view(dead_view))
				prev = TAILQ_PREV(dead_view,
				    tog_view_list_head, entry);
			else if (view->parent != dead_view)
				prev = view->parent;

			if (dead_view->parent)
				dead_view->parent->child = NULL;
			else
				TAILQ_REMOVE(&views, dead_view, entry);

			err = view_close(dead_view);
			if (err || dead_view == main_view)
				goto done;

			if (view == dead_view) {
				if (focus_view)
					view = focus_view;
				else if (prev)
					view = prev;
				else if (!TAILQ_EMPTY(&views))
					view = TAILQ_LAST(&views,
					    tog_view_list_head);
				else
					view = NULL;
				if (view) {
					if (view->child && view->child_focussed)
						focus_view = view->child;
					else
						focus_view = view;
				}
			}
		}
		if (new_view) {
			struct tog_view *v, *t;
			/* Only allow one parent view per type. */
			TAILQ_FOREACH_SAFE(v, &views, entry, t) {
				if (v->type != new_view->type)
					continue;
				TAILQ_REMOVE(&views, v, entry);
				err = view_close(v);
				if (err)
					goto done;
				break;
			}
			TAILQ_INSERT_TAIL(&views, new_view, entry);
			view = new_view;
			if (focus_view == NULL)
				focus_view = new_view;
		}
		if (focus_view) {
			show_panel(focus_view->panel);
			if (view)
				view->focussed = 0;
			focus_view->focussed = 1;
			view = focus_view;
			if (new_view)
				show_panel(new_view->panel);
			if (view->child && view_is_splitscreen(view->child))
				show_panel(view->child->panel);
		}
		if (view) {
			if (focus_view == NULL) {
				view->focussed = 1;
				show_panel(view->panel);
				if (view->child && view_is_splitscreen(view->child))
					show_panel(view->child->panel);
				focus_view = view;
			}
			if (view->parent) {
				err = view->parent->show(view->parent);
				if (err)
					goto done;
			}
			err = view->show(view);
			if (err)
				goto done;
			if (view->child) {
				err = view->child->show(view->child);
				if (err)
					goto done;
			}
			update_panels();
			doupdate();
		}
	}
done:
	while (!TAILQ_EMPTY(&views)) {
		view = TAILQ_FIRST(&views);
		TAILQ_REMOVE(&views, view, entry);
		view_close(view);
	}

	errcode = pthread_mutex_unlock(&tog_mutex);
	if (errcode)
		return got_error_set_errno(errcode);

	return err;
}

__dead static void
usage_log(void)
{
	endwin();
	fprintf(stderr,
	    "usage: %s log [-c commit] [-r repository-path] [path]\n",
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
			if (cols + width <= wlimit)
				cols += width;
			i++;
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

static const struct got_error*
build_refs_str(char **refs_str, struct got_reflist_head *refs,
    struct got_object_id *id)
{
	static const struct got_error *err = NULL;
	struct got_reflist_entry *re;
	char *s;
	const char *name;

	*refs_str = NULL;

	SIMPLEQ_FOREACH(re, refs, entry) {
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
		s = *refs_str;
		if (asprintf(refs_str, "%s%s%s", s ? s : "",
		    s ? ", " : "", name) == -1) {
			err = got_error_from_errno();
			free(s);
			*refs_str = NULL;
			break;
		}
		free(s);
	}

	return err;
}

static const struct got_error *
draw_commit(struct tog_view *view, struct got_commit_object *commit,
    struct got_object_id *id, struct got_reflist_head *refs)
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
	const int avail = view->ncols;
	struct tm tm;
	time_t committer_time;

	committer_time = got_object_commit_get_committer_time(commit);
	if (localtime_r(&committer_time, &tm) == NULL)
		return got_error_from_errno();
	if (strftime(datebuf, sizeof(datebuf), "%g/%m/%d ", &tm)
	    >= sizeof(datebuf))
		return got_error(GOT_ERR_NO_SPACE);

	if (avail < date_display_cols)
		limit = MIN(sizeof(datebuf) - 1, avail);
	else
		limit = MIN(date_display_cols, sizeof(datebuf) - 1);
	waddnstr(view->window, datebuf, limit);
	col = limit + 1;
	if (col > avail)
		goto done;

	author0 = strdup(got_object_commit_get_author(commit));
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
	waddwstr(view->window, wauthor);
	col += author_width;
	while (col <= avail && author_width < author_display_cols + 1) {
		waddch(view->window, ' ');
		col++;
		author_width++;
	}
	if (col > avail)
		goto done;

	logmsg0 = strdup(got_object_commit_get_logmsg(commit));
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
	waddwstr(view->window, wlogmsg);
	col += logmsg_width;
	while (col <= avail) {
		waddch(view->window, ' ');
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

	entry = TAILQ_FIRST(&commits->head);
	TAILQ_REMOVE(&commits->head, entry, entry);
	got_object_commit_close(entry->commit);
	commits->ncommits--;
	/* Don't free entry->id! It is owned by the commit graph. */
	free(entry);
}

static void
free_commits(struct commit_queue *commits)
{
	while (!TAILQ_EMPTY(&commits->head))
		pop_commit(commits);
}

static const struct got_error *
queue_commits(struct got_commit_graph *graph, struct commit_queue *commits,
    int minqueue, struct got_repository *repo, const char *path)
{
	const struct got_error *err = NULL;
	int nqueued = 0;

	/*
	 * We keep all commits open throughout the lifetime of the log
	 * view in order to avoid having to re-fetch commits from disk
	 * while updating the display.
	 */
	while (nqueued < minqueue) {
		struct got_object_id *id;
		struct got_commit_object *commit;
		struct commit_queue_entry *entry;
		int errcode;

		err = got_commit_graph_iter_next(&id, graph);
		if (err) {
			if (err->code != GOT_ERR_ITER_NEED_MORE)
				break;
			err = got_commit_graph_fetch_commits(graph,
			    minqueue, repo);
			if (err)
				return err;
			continue;
		}

		if (id == NULL)
			break;

		err = got_object_open_as_commit(&commit, repo, id);
		if (err)
			break;
		entry = alloc_commit_queue_entry(commit, id);
		if (entry == NULL) {
			err = got_error_from_errno();
			break;
		}

		errcode = pthread_mutex_lock(&tog_mutex);
		if (errcode) {
			err = got_error_set_errno(errcode);
			break;
		}

		entry->idx = commits->ncommits;
		TAILQ_INSERT_TAIL(&commits->head, entry, entry);
		nqueued++;
		commits->ncommits++;

		errcode = pthread_mutex_unlock(&tog_mutex);
		if (errcode && err == NULL)
			err = got_error_set_errno(errcode);
	}

	return err;
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
draw_commits(struct tog_view *view, struct commit_queue_entry **last,
    struct commit_queue_entry **selected, struct commit_queue_entry *first,
    struct commit_queue *commits, int selected_idx, int limit,
    struct got_reflist_head *refs, const char *path, int commits_needed)
{
	const struct got_error *err = NULL;
	struct commit_queue_entry *entry;
	int ncommits, width;
	char *id_str = NULL, *header = NULL, *ncommits_str = NULL;
	char *refs_str = NULL;
	wchar_t *wline;

	entry = first;
	ncommits = 0;
	while (entry) {
		if (ncommits == selected_idx) {
			*selected = entry;
			break;
		}
		entry = TAILQ_NEXT(entry, entry);
		ncommits++;
	}

	if (*selected) {
		err = got_object_id_str(&id_str, (*selected)->id);
		if (err)
			return err;
		if (refs) {
			err = build_refs_str(&refs_str, refs, (*selected)->id);
			if (err)
				goto done;
		}
	}

	if (commits_needed == 0)
		halfdelay(10); /* disable fast refresh */

	if (asprintf(&ncommits_str, " [%d/%d] %s",
	    entry ? entry->idx + 1 : 0, commits->ncommits,
	    commits_needed > 0 ? "loading... " :
	    (refs_str ? refs_str : "")) == -1) {
		err = got_error_from_errno();
		goto done;
	}

	if (path && strcmp(path, "/") != 0) {
		if (asprintf(&header, "commit %s %s%s",
		    id_str ? id_str : "........................................",
		    path, ncommits_str) == -1) {
			err = got_error_from_errno();
			header = NULL;
			goto done;
		}
	} else if (asprintf(&header, "commit %s%s",
	    id_str ? id_str : "........................................",
	    ncommits_str) == -1) {
		err = got_error_from_errno();
		header = NULL;
		goto done;
	}
	err = format_line(&wline, &width, header, view->ncols);
	if (err)
		goto done;

	werase(view->window);

	if (view_needs_focus_indication(view))
		wstandout(view->window);
	waddwstr(view->window, wline);
	while (width < view->ncols) {
		waddch(view->window, ' ');
		width++;
	}
	if (view_needs_focus_indication(view))
		wstandend(view->window);
	free(wline);
	if (limit <= 1)
		goto done;

	entry = first;
	*last = first;
	ncommits = 0;
	while (entry) {
		if (ncommits >= limit - 1)
			break;
		if (view->focussed && ncommits == selected_idx)
			wstandout(view->window);
		err = draw_commit(view, entry->commit, entry->id, refs);
		if (view->focussed && ncommits == selected_idx)
			wstandend(view->window);
		if (err)
			break;
		ncommits++;
		*last = entry;
		entry = TAILQ_NEXT(entry, entry);
	}

	view_vborder(view);
done:
	free(id_str);
	free(refs_str);
	free(ncommits_str);
	free(header);
	return err;
}

static void
scroll_up(struct commit_queue_entry **first_displayed_entry, int maxscroll,
    struct commit_queue *commits)
{
	struct commit_queue_entry *entry;
	int nscrolled = 0;

	entry = TAILQ_FIRST(&commits->head);
	if (*first_displayed_entry == entry)
		return;

	entry = *first_displayed_entry;
	while (entry && nscrolled < maxscroll) {
		entry = TAILQ_PREV(entry, commit_queue_head, entry);
		if (entry) {
			*first_displayed_entry = entry;
			nscrolled++;
		}
	}
}

static const struct got_error *
trigger_log_thread(int load_all, int *commits_needed, int *log_complete,
    pthread_cond_t *need_commits)
{
	int errcode;

	while (*commits_needed > 0) {
		if (*log_complete)
			break;

		/* Wake the log thread. */
		errcode = pthread_cond_signal(need_commits);
		if (errcode)
			return got_error_set_errno(errcode);
		errcode = pthread_mutex_unlock(&tog_mutex);
		if (errcode)
			return got_error_set_errno(errcode);
		pthread_yield();
		errcode = pthread_mutex_lock(&tog_mutex);
		if (errcode)
			return got_error_set_errno(errcode);

		if (*commits_needed > 0 && !load_all) {
			/*
			 * Thread is not done yet; lose a key press
			 * and let the user retry... this way the GUI
			 * remains interactive while logging deep paths
			 * with few commits in history.
			 */
			halfdelay(1); /* fast refresh while loading */
			return NULL;
		}
	}

	return NULL;
}

static const struct got_error *
scroll_down(struct commit_queue_entry **first_displayed_entry, int maxscroll,
    struct commit_queue_entry **last_displayed_entry,
    struct commit_queue *commits, int *log_complete, int *commits_needed,
    pthread_cond_t *need_commits)
{
	const struct got_error *err = NULL;
	struct commit_queue_entry *pentry;
	int nscrolled = 0;

	if (*last_displayed_entry == NULL)
		return NULL;

	pentry = TAILQ_NEXT(*last_displayed_entry, entry);
	if (pentry == NULL && !*log_complete) {
		(*commits_needed) += maxscroll;
		err = trigger_log_thread(0, commits_needed, log_complete,
		    need_commits);
		if (err)
			return err;
	}

	do {
		pentry = TAILQ_NEXT(*last_displayed_entry, entry);
		if (pentry == NULL)
			break;

		*last_displayed_entry = pentry;

		pentry = TAILQ_NEXT(*first_displayed_entry, entry);
		if (pentry == NULL)
			break;
		*first_displayed_entry = pentry;
	} while (++nscrolled < maxscroll);

	return err;
}

static const struct got_error *
open_diff_view_for_commit(struct tog_view **new_view, int begin_x,
    struct got_commit_object *commit, struct got_object_id *commit_id,
    struct tog_view *log_view, struct got_reflist_head *refs,
    struct got_repository *repo)
{
	const struct got_error *err;
	struct got_object_qid *parent_id;
	struct tog_view *diff_view;

	diff_view = view_open(0, 0, 0, begin_x, TOG_VIEW_DIFF);
	if (diff_view == NULL)
		return got_error_from_errno();

	parent_id = SIMPLEQ_FIRST(got_object_commit_get_parent_ids(commit));
	err = open_diff_view(diff_view, parent_id ? parent_id->id : NULL,
	    commit_id, log_view, refs, repo);
	if (err == NULL)
		*new_view = diff_view;
	return err;
}

static const struct got_error *
browse_commit(struct tog_view **new_view, int begin_x,
    struct commit_queue_entry *entry, struct got_reflist_head *refs,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_tree_object *tree;
	struct tog_view *tree_view;

	err = got_object_open_as_tree(&tree, repo,
	    got_object_commit_get_tree_id(entry->commit));
	if (err)
		return err;

	tree_view = view_open(0, 0, 0, begin_x, TOG_VIEW_TREE);
	if (tree_view == NULL)
		return got_error_from_errno();

	err = open_tree_view(tree_view, tree, entry->id, refs, repo);
	if (err)
		got_object_tree_close(tree);
	else
		*new_view = tree_view;
	return err;
}

static void *
log_thread(void *arg)
{
	const struct got_error *err = NULL;
	int errcode = 0;
	struct tog_log_thread_args *a = arg;
	int done = 0;

	err = got_commit_graph_iter_start(a->graph, a->start_id, a->repo);
	if (err)
		return (void *)err;

	while (!done && !err) {
		err = queue_commits(a->graph, a->commits, 1, a->repo,
		    a->in_repo_path);
		if (err) {
			if (err->code != GOT_ERR_ITER_COMPLETED)
				return (void *)err;
			err = NULL;
			done = 1;
		} else if (a->commits_needed > 0)
			a->commits_needed--;

		errcode = pthread_mutex_lock(&tog_mutex);
		if (errcode)
			return (void *)got_error_set_errno(errcode);

		if (done)
			a->log_complete = 1;
		else if (*a->quit) {
			done = 1;
			a->log_complete = 1;
		} else if (*a->first_displayed_entry == NULL) {
			*a->first_displayed_entry =
			    TAILQ_FIRST(&a->commits->head);
			*a->selected_entry = *a->first_displayed_entry;
		}

		if (done)
			a->commits_needed = 0;
		else if (a->commits_needed == 0) {
			errcode = pthread_cond_wait(&a->need_commits,
			    &tog_mutex);
			if (errcode)
				err = got_error_set_errno(errcode);
		}

		errcode = pthread_mutex_unlock(&tog_mutex);
		if (errcode && err == NULL)
			err = got_error_set_errno(errcode);
	}
	return (void *)err;
}

static const struct got_error *
stop_log_thread(struct tog_log_view_state *s)
{
	const struct got_error *err = NULL;
	int errcode;

	if (s->thread) {
		s->quit = 1;
		errcode = pthread_cond_signal(&s->thread_args.need_commits);
		if (errcode)
			return got_error_set_errno(errcode);
		errcode = pthread_mutex_unlock(&tog_mutex);
		if (errcode)
			return got_error_set_errno(errcode);
		errcode = pthread_join(s->thread, (void **)&err);
		if (errcode)
			return got_error_set_errno(errcode);
		errcode = pthread_mutex_lock(&tog_mutex);
		if (errcode)
			return got_error_set_errno(errcode);
		s->thread = NULL;
	}

	errcode = pthread_cond_destroy(&s->thread_args.need_commits);
	if (errcode && err == NULL)
		err = got_error_set_errno(errcode);

	if (s->thread_args.repo) {
		got_repo_close(s->thread_args.repo);
		s->thread_args.repo = NULL;
	}

	if (s->thread_args.graph) {
		got_commit_graph_close(s->thread_args.graph);
		s->thread_args.graph = NULL;
	}

	return err;
}

static const struct got_error *
close_log_view(struct tog_view *view)
{
	const struct got_error *err = NULL;
	struct tog_log_view_state *s = &view->state.log;

	err = stop_log_thread(s);
	free_commits(&s->commits);
	free(s->in_repo_path);
	s->in_repo_path = NULL;
	free(s->start_id);
	s->start_id = NULL;
	return err;
}

static const struct got_error *
open_log_view(struct tog_view *view, struct got_object_id *start_id,
    struct got_reflist_head *refs, struct got_repository *repo,
    const char *path, int check_disk)
{
	const struct got_error *err = NULL;
	struct tog_log_view_state *s = &view->state.log;
	struct got_repository *thread_repo = NULL;
	struct got_commit_graph *thread_graph = NULL;
	int errcode;

	err = got_repo_map_path(&s->in_repo_path, repo, path, check_disk);
	if (err != NULL)
		goto done;

	/* The commit queue only contains commits being displayed. */
	TAILQ_INIT(&s->commits.head);
	s->commits.ncommits = 0;

	s->refs = refs;
	s->repo = repo;
	s->start_id = got_object_id_dup(start_id);
	if (s->start_id == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	view->show = show_log_view;
	view->input = input_log_view;
	view->close = close_log_view;

	err = got_repo_open(&thread_repo, got_repo_get_path(repo));
	if (err)
		goto done;
	err = got_commit_graph_open(&thread_graph, start_id, s->in_repo_path,
	    0, thread_repo);
	if (err)
		goto done;

	errcode = pthread_cond_init(&s->thread_args.need_commits, NULL);
	if (errcode) {
		err = got_error_set_errno(errcode);
		goto done;
	}

	s->thread_args.commits_needed = view->nlines;
	s->thread_args.graph = thread_graph;
	s->thread_args.commits = &s->commits;
	s->thread_args.in_repo_path = s->in_repo_path;
	s->thread_args.start_id = s->start_id;
	s->thread_args.repo = thread_repo;
	s->thread_args.log_complete = 0;
	s->thread_args.quit = &s->quit;
	s->thread_args.view = view;
	s->thread_args.first_displayed_entry = &s->first_displayed_entry;
	s->thread_args.selected_entry = &s->selected_entry;
done:
	if (err)
		close_log_view(view);
	return err;
}

static const struct got_error *
show_log_view(struct tog_view *view)
{
	struct tog_log_view_state *s = &view->state.log;

	if (s->thread == NULL) {
		int errcode = pthread_create(&s->thread, NULL, log_thread,
		    &s->thread_args);
		if (errcode)
			return got_error_set_errno(errcode);
	}

	return draw_commits(view, &s->last_displayed_entry,
	    &s->selected_entry, s->first_displayed_entry,
	    &s->commits, s->selected, view->nlines, s->refs,
	    s->in_repo_path, s->thread_args.commits_needed);
}

static const struct got_error *
input_log_view(struct tog_view **new_view, struct tog_view **dead_view,
    struct tog_view **focus_view, struct tog_view *view, int ch)
{
	const struct got_error *err = NULL;
	struct tog_log_view_state *s = &view->state.log;
	char *parent_path;
	struct tog_view *diff_view = NULL, *tree_view = NULL;
	int begin_x = 0;

	switch (ch) {
		case 'q':
			s->quit = 1;
			break;
		case 'k':
		case KEY_UP:
		case '<':
		case ',':
			if (s->first_displayed_entry == NULL)
				break;
			if (s->selected > 0)
				s->selected--;
			if (s->selected > 0)
				break;
			scroll_up(&s->first_displayed_entry, 1,
			    &s->commits);
			break;
		case KEY_PPAGE:
			if (s->first_displayed_entry == NULL)
				break;
			if (TAILQ_FIRST(&s->commits.head) ==
			    s->first_displayed_entry) {
				s->selected = 0;
				break;
			}
			scroll_up(&s->first_displayed_entry,
			    view->nlines, &s->commits);
			break;
		case 'j':
		case KEY_DOWN:
		case '>':
		case '.':
			if (s->first_displayed_entry == NULL)
				break;
			if (s->selected < MIN(view->nlines - 2,
			    s->commits.ncommits - 1)) {
				s->selected++;
				break;
			}
			err = scroll_down(&s->first_displayed_entry, 1,
			    &s->last_displayed_entry, &s->commits,
			    &s->thread_args.log_complete,
			    &s->thread_args.commits_needed,
			    &s->thread_args.need_commits);
			break;
		case KEY_NPAGE: {
			struct commit_queue_entry *first;
			first = s->first_displayed_entry;
			if (first == NULL)
				break;
			err = scroll_down(&s->first_displayed_entry,
			    view->nlines, &s->last_displayed_entry,
			    &s->commits, &s->thread_args.log_complete,
			    &s->thread_args.commits_needed,
			    &s->thread_args.need_commits);
			if (first == s->first_displayed_entry &&
			    s->selected < MIN(view->nlines - 2,
			    s->commits.ncommits - 1)) {
				/* can't scroll further down */
				s->selected = MIN(view->nlines - 2,
				    s->commits.ncommits - 1);
			}
			err = NULL;
			break;
		}
		case KEY_RESIZE:
			if (s->selected > view->nlines - 2)
				s->selected = view->nlines - 2;
			if (s->selected > s->commits.ncommits - 1)
				s->selected = s->commits.ncommits - 1;
			break;
		case KEY_ENTER:
		case '\r':
			if (s->selected_entry == NULL)
				break;
			if (view_is_parent_view(view))
				begin_x = view_split_begin_x(view->begin_x);
			err = open_diff_view_for_commit(&diff_view, begin_x,
			    s->selected_entry->commit, s->selected_entry->id,
			    view, s->refs, s->repo);
			if (err)
				break;
			if (view_is_parent_view(view)) {
				err = view_close_child(view);
				if (err)
					return err;
				err = view_set_child(view, diff_view);
				if (err) {
					view_close(diff_view);
					break;
				}
				*focus_view = diff_view;
				view->child_focussed = 1;
			} else
				*new_view = diff_view;
			break;
		case 't':
			if (s->selected_entry == NULL)
				break;
			if (view_is_parent_view(view))
				begin_x = view_split_begin_x(view->begin_x);
			err = browse_commit(&tree_view, begin_x,
			    s->selected_entry, s->refs, s->repo);
			if (err)
				break;
			if (view_is_parent_view(view)) {
				err = view_close_child(view);
				if (err)
					return err;
				err = view_set_child(view, tree_view);
				if (err) {
					view_close(tree_view);
					break;
				}
				*focus_view = tree_view;
				view->child_focussed = 1;
			} else
				*new_view = tree_view;
			break;
		case KEY_BACKSPACE:
			if (strcmp(s->in_repo_path, "/") == 0)
				break;
			parent_path = dirname(s->in_repo_path);
			if (parent_path && strcmp(parent_path, ".") != 0) {
				struct tog_view *lv;
				err = stop_log_thread(s);
				if (err)
					return err;
				lv = view_open(view->nlines, view->ncols,
				    view->begin_y, view->begin_x, TOG_VIEW_LOG);
				if (lv == NULL)
					return got_error_from_errno();
				err = open_log_view(lv, s->start_id, s->refs,
				    s->repo, parent_path, 0);
				if (err)
					return err;;
				if (view_is_parent_view(view))
					*new_view = lv;
				else {
					view_set_child(view->parent, lv);
					*focus_view = lv;
				}
				return NULL;
			}
			break;
		default:
			break;
	}

	return err;
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

static void
init_curses(void)
{
	initscr();
	cbreak();
	halfdelay(1); /* Do fast refresh while initial view is loading. */
	noecho();
	nonl();
	intrflush(stdscr, FALSE);
	keypad(stdscr, TRUE);
	curs_set(0);
	signal(SIGWINCH, tog_sigwinch);
}

static const struct got_error *
cmd_log(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	struct got_reflist_head refs;
	struct got_object_id *start_id = NULL;
	char *path = NULL, *repo_path = NULL, *cwd = NULL;
	char *start_commit = NULL;
	int ch;
	struct tog_view *view;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc tty exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "c:r:")) != -1) {
		switch (ch) {
		case 'c':
			start_commit = optarg;
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
		struct got_worktree *worktree;
		error = got_worktree_open(&worktree, cwd);
		if (error && error->code != GOT_ERR_NOT_WORKTREE)
			goto done;
		if (worktree) {
			repo_path =
			    strdup(got_worktree_get_repo_path(worktree));
			got_worktree_close(worktree);
		} else
			repo_path = strdup(cwd);
		if (repo_path == NULL) {
			error = got_error_from_errno();
			goto done;
		}
	}

	init_curses();

	error = apply_unveil(repo_path, NULL);
	if (error)
		goto done;

	error = got_repo_open(&repo, repo_path);
	if (error != NULL)
		goto done;

	if (start_commit == NULL)
		error = get_head_commit_id(&start_id, repo);
	else
		error = got_object_resolve_id_str(&start_id, repo,
		    start_commit);
	if (error != NULL)
		goto done;

	SIMPLEQ_INIT(&refs);
	error = got_ref_list(&refs, repo);
	if (error)
		goto done;

	view = view_open(0, 0, 0, 0, TOG_VIEW_LOG);
	if (view == NULL) {
		error = got_error_from_errno();
		goto done;
	}
	error = open_log_view(view, start_id, &refs, repo, path, 1);
	if (error)
		goto done;
	error = view_loop(view);
done:
	free(repo_path);
	free(cwd);
	free(path);
	free(start_id);
	if (repo)
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
draw_file(struct tog_view *view, FILE *f, int *first_displayed_line,
    int *last_displayed_line, int *eof, int max_lines,
    char * header)
{
	const struct got_error *err;
	int nlines = 0, nprinted = 0;
	char *line;
	size_t len;
	wchar_t *wline;
	int width;

	rewind(f);
	werase(view->window);

	if (header) {
		err = format_line(&wline, &width, header, view->ncols);
		if (err) {
			return err;
		}

		if (view_needs_focus_indication(view))
			wstandout(view->window);
		waddwstr(view->window, wline);
		if (view_needs_focus_indication(view))
			wstandend(view->window);
		if (width < view->ncols)
			waddch(view->window, '\n');

		if (max_lines <= 1)
			return NULL;
		max_lines--;
	}

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

		err = format_line(&wline, &width, line, view->ncols);
		if (err) {
			free(line);
			return err;
		}
		waddwstr(view->window, wline);
		if (width < view->ncols)
			waddch(view->window, '\n');
		if (++nprinted == 1)
			*first_displayed_line = nlines;
		free(line);
		free(wline);
		wline = NULL;
	}
	*last_displayed_line = nlines;

	view_vborder(view);

	return NULL;
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
write_commit_info(struct got_object_id *commit_id,
    struct got_reflist_head *refs, struct got_repository *repo, FILE *outfile)
{
	const struct got_error *err = NULL;
	char datebuf[26];
	struct got_commit_object *commit;
	char *id_str = NULL;
	time_t committer_time;
	const char *author, *committer;
	char *refs_str = NULL;

	if (refs) {
		err = build_refs_str(&refs_str, refs, commit_id);
		if (err)
			return err;
	}

	err = got_object_open_as_commit(&commit, repo, commit_id);
	if (err)
		return err;

	err = got_object_id_str(&id_str, commit_id);
	if (err) {
		err = got_error_from_errno();
		goto done;
	}

	if (fprintf(outfile, "commit %s%s%s%s\n", id_str, refs_str ? " (" : "",
	    refs_str ? refs_str : "", refs_str ? ")" : "") < 0) {
		err = got_error_from_errno();
		goto done;
	}
	if (fprintf(outfile, "from: %s\n",
	    got_object_commit_get_author(commit)) < 0) {
		err = got_error_from_errno();
		goto done;
	}
	committer_time = got_object_commit_get_committer_time(commit);
	if (fprintf(outfile, "date: %s UTC\n",
	    get_datestr(&committer_time, datebuf)) < 0) {
		err = got_error_from_errno();
		goto done;
	}
	author = got_object_commit_get_author(commit);
	committer = got_object_commit_get_committer(commit);
	if (strcmp(author, committer) != 0 &&
	    fprintf(outfile, "via: %s\n", committer) < 0) {
		err = got_error_from_errno();
		goto done;
	}
	if (fprintf(outfile, "%s\n",
	    got_object_commit_get_logmsg(commit)) < 0) {
		err = got_error_from_errno();
		goto done;
	}
done:
	free(id_str);
	free(refs_str);
	got_object_commit_close(commit);
	return err;
}

static const struct got_error *
create_diff(struct tog_diff_view_state *s)
{
	const struct got_error *err = NULL;
	FILE *f = NULL;
	int obj_type;

	f = got_opentemp();
	if (f == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	if (s->f && fclose(s->f) != 0) {
		err = got_error_from_errno();
		goto done;
	}
	s->f = f;

	if (s->id1)
		err = got_object_get_type(&obj_type, s->repo, s->id1);
	else
		err = got_object_get_type(&obj_type, s->repo, s->id2);
	if (err)
		goto done;

	switch (obj_type) {
	case GOT_OBJ_TYPE_BLOB:
		err = got_diff_objects_as_blobs(s->id1, s->id2, NULL, NULL,
		    s->diff_context, s->repo, f);
		break;
	case GOT_OBJ_TYPE_TREE:
		err = got_diff_objects_as_trees(s->id1, s->id2, "", "",
		    s->diff_context, s->repo, f);
		break;
	case GOT_OBJ_TYPE_COMMIT: {
		const struct got_object_id_queue *parent_ids;
		struct got_object_qid *pid;
		struct got_commit_object *commit2;

		err = got_object_open_as_commit(&commit2, s->repo, s->id2);
		if (err)
			break;
		/* Show commit info if we're diffing to a parent/root commit. */
		if (s->id1 == NULL)
			write_commit_info(s->id2, s->refs, s->repo, f);
		else {
			parent_ids = got_object_commit_get_parent_ids(commit2);
			SIMPLEQ_FOREACH(pid, parent_ids, entry) {
				if (got_object_id_cmp(s->id1, pid->id) == 0) {
					write_commit_info(s->id2, s->refs,
					    s->repo, f);
					break;
				}
			}
		}
		got_object_commit_close(commit2);

		err = got_diff_objects_as_commits(s->id1, s->id2,
		    s->diff_context, s->repo, f);
		break;
	}
	default:
		err = got_error(GOT_ERR_OBJ_TYPE);
		break;
	}
done:
	if (f && fflush(f) != 0 && err == NULL)
		err = got_error_from_errno();
	return err;
}

static const struct got_error *
open_diff_view(struct tog_view *view, struct got_object_id *id1,
    struct got_object_id *id2, struct tog_view *log_view,
    struct got_reflist_head *refs, struct got_repository *repo)
{
	const struct got_error *err;

	if (id1 != NULL && id2 != NULL) {
	    int type1, type2;
	    err = got_object_get_type(&type1, repo, id1);
	    if (err)
		return err;
	    err = got_object_get_type(&type2, repo, id2);
	    if (err)
		return err;

	    if (type1 != type2)
		return got_error(GOT_ERR_OBJ_TYPE);
	}

	if (id1) {
		view->state.diff.id1 = got_object_id_dup(id1);
		if (view->state.diff.id1 == NULL)
			return got_error_from_errno();
	} else
		view->state.diff.id1 = NULL;

	view->state.diff.id2 = got_object_id_dup(id2);
	if (view->state.diff.id2 == NULL) {
		free(view->state.diff.id1);
		view->state.diff.id1 = NULL;
		return got_error_from_errno();
	}
	view->state.diff.f = NULL;
	view->state.diff.first_displayed_line = 1;
	view->state.diff.last_displayed_line = view->nlines;
	view->state.diff.diff_context = 3;
	view->state.diff.log_view = log_view;
	view->state.diff.repo = repo;
	view->state.diff.refs = refs;

	err = create_diff(&view->state.diff);
	if (err) {
		free(view->state.diff.id1);
		view->state.diff.id1 = NULL;
		free(view->state.diff.id2);
		view->state.diff.id2 = NULL;
		return err;
	}

	view->show = show_diff_view;
	view->input = input_diff_view;
	view->close = close_diff_view;

	return NULL;
}

static const struct got_error *
close_diff_view(struct tog_view *view)
{
	const struct got_error *err = NULL;

	free(view->state.diff.id1);
	view->state.diff.id1 = NULL;
	free(view->state.diff.id2);
	view->state.diff.id2 = NULL;
	if (view->state.diff.f && fclose(view->state.diff.f) == EOF)
		err = got_error_from_errno();
	return err;
}

static const struct got_error *
show_diff_view(struct tog_view *view)
{
	const struct got_error *err;
	struct tog_diff_view_state *s = &view->state.diff;
	char *id_str1 = NULL, *id_str2, *header;

	if (s->id1) {
		err = got_object_id_str(&id_str1, s->id1);
		if (err)
			return err;
	}
	err = got_object_id_str(&id_str2, s->id2);
	if (err)
		return err;

	if (asprintf(&header, "diff %s %s",
	    id_str1 ? id_str1 : "/dev/null", id_str2) == -1) {
		err = got_error_from_errno();
		free(id_str1);
		free(id_str2);
		return err;
	}
	free(id_str1);
	free(id_str2);

	return draw_file(view, s->f, &s->first_displayed_line,
	    &s->last_displayed_line, &s->eof, view->nlines,
	    header);
}

static const struct got_error *
set_selected_commit(struct tog_diff_view_state *s,
    struct commit_queue_entry *entry)
{
	const struct got_error *err;
	const struct got_object_id_queue *parent_ids;
	struct got_commit_object *selected_commit;
	struct got_object_qid *pid;

	free(s->id2);
	s->id2 = got_object_id_dup(entry->id);
	if (s->id2 == NULL)
		return got_error_from_errno();

	err = got_object_open_as_commit(&selected_commit, s->repo, entry->id);
	if (err)
		return err;
	parent_ids = got_object_commit_get_parent_ids(selected_commit);
	free(s->id1);
	pid = SIMPLEQ_FIRST(parent_ids);
	s->id1 = pid ? got_object_id_dup(pid->id) : NULL;
	got_object_commit_close(selected_commit);
	return NULL;
}

static const struct got_error *
input_diff_view(struct tog_view **new_view, struct tog_view **dead_view,
    struct tog_view **focus_view, struct tog_view *view, int ch)
{
	const struct got_error *err = NULL;
	struct tog_diff_view_state *s = &view->state.diff;
	struct tog_log_view_state *ls;
	struct commit_queue_entry *entry;
	int i;

	switch (ch) {
		case 'k':
		case KEY_UP:
			if (s->first_displayed_line > 1)
				s->first_displayed_line--;
			break;
		case KEY_PPAGE:
			i = 0;
			while (i++ < view->nlines - 1 &&
			    s->first_displayed_line > 1)
				s->first_displayed_line--;
			break;
		case 'j':
		case KEY_DOWN:
			if (!s->eof)
				s->first_displayed_line++;
			break;
		case KEY_NPAGE:
		case ' ':
			i = 0;
			while (!s->eof && i++ < view->nlines - 1) {
				char *line;
				line = parse_next_line(s->f, NULL);
				s->first_displayed_line++;
				if (line == NULL)
					break;
			}
			break;
		case '[':
			if (s->diff_context > 0) {
				s->diff_context--;
				err = create_diff(s);
			}
			break;
		case ']':
			if (s->diff_context < GOT_DIFF_MAX_CONTEXT) {
				s->diff_context++;
				err = create_diff(s);
			}
			break;
		case '<':
		case ',':
			if (s->log_view == NULL)
				break;
			ls = &s->log_view->state.log;
			entry = TAILQ_PREV(ls->selected_entry,
			    commit_queue_head, entry);
			if (entry == NULL)
				break;

			err = input_log_view(NULL, NULL, NULL, s->log_view,
			    KEY_UP);
			if (err)
				break;

			err = set_selected_commit(s, entry);
			if (err)
				break;

			s->first_displayed_line = 1;
			s->last_displayed_line = view->nlines;

			err = create_diff(s);
			break;
		case '>':
		case '.':
			if (s->log_view == NULL)
				break;
			ls = &s->log_view->state.log;

			if (ls->thread_args.commits_needed == 0) {
				ls->thread_args.commits_needed++;

				/* Display "loading..." in log view. */
				show_log_view(s->log_view);
				update_panels();
				doupdate();
			}
			err = trigger_log_thread(1 /* load_all */,
			    &ls->thread_args.commits_needed,
			    &ls->thread_args.log_complete,
			    &ls->thread_args.need_commits);
			if (err)
				break;

			err = input_log_view(NULL, NULL, NULL, s->log_view,
			    KEY_DOWN);
			if (err)
				break;

			entry = TAILQ_NEXT(ls->selected_entry, entry);
			if (entry == NULL)
				break;

			err = set_selected_commit(s, entry);
			if (err)
				break;

			s->first_displayed_line = 1;
			s->last_displayed_line = view->nlines;

			err = create_diff(s);
			break;
		default:
			break;
	}

	return err;
}

static const struct got_error *
cmd_diff(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_reflist_head refs;
	struct got_object_id *id1 = NULL, *id2 = NULL;
	char *repo_path = NULL;
	char *id_str1 = NULL, *id_str2 = NULL;
	int ch;
	struct tog_view *view;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc tty exec sendfd unveil",
	    NULL) == -1)
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
		id_str1 = argv[0];
		id_str2 = argv[1];
	} else if (argc == 3) {
		repo_path = realpath(argv[0], NULL);
		if (repo_path == NULL)
			return got_error_from_errno();
		id_str1 = argv[1];
		id_str2 = argv[2];
	} else
		usage_diff();

	init_curses();

	error = apply_unveil(repo_path, NULL);
	if (error)
		goto done;

	error = got_repo_open(&repo, repo_path);
	free(repo_path);
	if (error)
		goto done;

	error = got_object_resolve_id_str(&id1, repo, id_str1);
	if (error)
		goto done;

	error = got_object_resolve_id_str(&id2, repo, id_str2);
	if (error)
		goto done;

	SIMPLEQ_INIT(&refs);
	error = got_ref_list(&refs, repo);
	if (error)
		goto done;

	view = view_open(0, 0, 0, 0, TOG_VIEW_DIFF);
	if (view == NULL) {
		error = got_error_from_errno();
		goto done;
	}
	error = open_diff_view(view, id1, id2, NULL, &refs, repo);
	if (error)
		goto done;
	error = view_loop(view);
done:
	got_repo_close(repo);
	return error;
}

__dead static void
usage_blame(void)
{
	endwin();
	fprintf(stderr, "usage: %s blame [-c commit] [-r repository-path] path\n",
	    getprogname());
	exit(1);
}

struct tog_blame_line {
	int annotated;
	struct got_object_id *id;
};

static const struct got_error *
draw_blame(struct tog_view *view, struct got_object_id *id, FILE *f,
    const char *path, struct tog_blame_line *lines, int nlines,
    int blame_complete, int selected_line, int *first_displayed_line,
    int *last_displayed_line, int *eof, int max_lines)
{
	const struct got_error *err;
	int lineno = 0, nprinted = 0;
	char *line;
	size_t len;
	wchar_t *wline;
	int width, wlimit;
	struct tog_blame_line *blame_line;
	struct got_object_id *prev_id = NULL;
	char *id_str;

	err = got_object_id_str(&id_str, id);
	if (err)
		return err;

	rewind(f);
	werase(view->window);

	if (asprintf(&line, "commit %s", id_str) == -1) {
		err = got_error_from_errno();
		free(id_str);
		return err;
	}

	err = format_line(&wline, &width, line, view->ncols);
	free(line);
	line = NULL;
	if (view_needs_focus_indication(view))
		wstandout(view->window);
	waddwstr(view->window, wline);
	if (view_needs_focus_indication(view))
		wstandend(view->window);
	free(wline);
	wline = NULL;
	if (width < view->ncols)
		waddch(view->window, '\n');

	if (asprintf(&line, "[%d/%d] %s%s",
	    *first_displayed_line - 1 + selected_line, nlines,
	    blame_complete ? "" : "annotating... ", path) == -1) {
		free(id_str);
		return got_error_from_errno();
	}
	free(id_str);
	err = format_line(&wline, &width, line, view->ncols);
	free(line);
	line = NULL;
	if (err)
		return err;
	waddwstr(view->window, wline);
	free(wline);
	wline = NULL;
	if (width < view->ncols)
		waddch(view->window, '\n');

	*eof = 0;
	while (nprinted < max_lines - 2) {
		line = parse_next_line(f, &len);
		if (line == NULL) {
			*eof = 1;
			break;
		}
		if (++lineno < *first_displayed_line) {
			free(line);
			continue;
		}

		wlimit = view->ncols < 9 ? 0 : view->ncols - 9;
		err = format_line(&wline, &width, line, wlimit);
		if (err) {
			free(line);
			return err;
		}

		if (view->focussed && nprinted == selected_line - 1)
			wstandout(view->window);

		blame_line = &lines[lineno - 1];
		if (blame_line->annotated && prev_id &&
		    got_object_id_cmp(prev_id, blame_line->id) == 0)
			waddstr(view->window, "         ");
		else if (blame_line->annotated) {
			char *id_str;
			err = got_object_id_str(&id_str, blame_line->id);
			if (err) {
				free(line);
				free(wline);
				return err;
			}
			wprintw(view->window, "%.8s ", id_str);
			free(id_str);
			prev_id = blame_line->id;
		} else {
			waddstr(view->window, "........ ");
			prev_id = NULL;
		}

		waddwstr(view->window, wline);
		while (width < wlimit) {
			waddch(view->window, ' ');
			width++;
		}
		if (view->focussed && nprinted == selected_line - 1)
			wstandend(view->window);
		if (++nprinted == 1)
			*first_displayed_line = lineno;
		free(line);
		free(wline);
		wline = NULL;
	}
	*last_displayed_line = lineno;

	view_vborder(view);

	return NULL;
}

static const struct got_error *
blame_cb(void *arg, int nlines, int lineno, struct got_object_id *id)
{
	const struct got_error *err = NULL;
	struct tog_blame_cb_args *a = arg;
	struct tog_blame_line *line;
	int errcode;

	if (nlines != a->nlines ||
	    (lineno != -1 && lineno < 1) || lineno > a->nlines)
		return got_error(GOT_ERR_RANGE);

	errcode = pthread_mutex_lock(&tog_mutex);
	if (errcode)
		return got_error_set_errno(errcode);

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
done:
	errcode = pthread_mutex_unlock(&tog_mutex);
	if (errcode)
		err = got_error_set_errno(errcode);
	return err;
}

static void *
blame_thread(void *arg)
{
	const struct got_error *err;
	struct tog_blame_thread_args *ta = arg;
	struct tog_blame_cb_args *a = ta->cb_args;
	int errcode;

	err = got_blame_incremental(ta->path, a->commit_id, ta->repo,
	    blame_cb, ta->cb_args);

	errcode = pthread_mutex_lock(&tog_mutex);
	if (errcode)
		return (void *)got_error_set_errno(errcode);

	got_repo_close(ta->repo);
	ta->repo = NULL;
	*ta->complete = 1;

	errcode = pthread_mutex_unlock(&tog_mutex);
	if (errcode && err == NULL)
		err = got_error_set_errno(errcode);

	return (void *)err;
}

static struct got_object_id *
get_selected_commit_id(struct tog_blame_line *lines, int first_displayed_line,
    int selected_line)
{
	struct tog_blame_line *line;

	line = &lines[first_displayed_line - 1 + selected_line - 1];
	if (!line->annotated)
		return NULL;

	return line->id;
}

static const struct got_error *
stop_blame(struct tog_blame *blame)
{
	const struct got_error *err = NULL;
	int i;

	if (blame->thread) {
		int errcode;
		errcode = pthread_mutex_unlock(&tog_mutex);
		if (errcode)
			return got_error_set_errno(errcode);
		errcode = pthread_join(blame->thread, (void **)&err);
		if (errcode)
			return got_error_set_errno(errcode);
		errcode = pthread_mutex_lock(&tog_mutex);
		if (errcode)
			return got_error_set_errno(errcode);
		if (err && err->code == GOT_ERR_ITER_COMPLETED)
			err = NULL;
		blame->thread = NULL;
	}
	if (blame->thread_args.repo) {
		got_repo_close(blame->thread_args.repo);
		blame->thread_args.repo = NULL;
	}
	if (blame->f) {
		if (fclose(blame->f) != 0 && err == NULL)
			err = got_error_from_errno();
		blame->f = NULL;
	}
	if (blame->lines) {
		for (i = 0; i < blame->nlines; i++)
			free(blame->lines[i].id);
		free(blame->lines);
		blame->lines = NULL;
	}
	free(blame->cb_args.commit_id);
	blame->cb_args.commit_id = NULL;

	return err;
}

static const struct got_error *
run_blame(struct tog_blame *blame, struct tog_view *view, int *blame_complete,
    int *first_displayed_line, int *last_displayed_line, int *selected_line,
    int *done, int *eof, const char *path, struct got_object_id *commit_id,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_blob_object *blob = NULL;
	struct got_repository *thread_repo = NULL;
	struct got_object_id *obj_id = NULL;
	int obj_type;

	err = got_object_id_by_path(&obj_id, repo, commit_id, path);
	if (err)
		return err;
	if (obj_id == NULL)
		return got_error(GOT_ERR_NO_OBJ);

	err = got_object_get_type(&obj_type, repo, obj_id);
	if (err)
		goto done;

	if (obj_type != GOT_OBJ_TYPE_BLOB) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = got_object_open_as_blob(&blob, repo, obj_id, 8192);
	if (err)
		goto done;
	blame->f = got_opentemp();
	if (blame->f == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	err = got_object_blob_dump_to_file(&blame->filesize, &blame->nlines,
	    blame->f, blob);
	if (err)
		goto done;

	blame->lines = calloc(blame->nlines, sizeof(*blame->lines));
	if (blame->lines == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	err = got_repo_open(&thread_repo, got_repo_get_path(repo));
	if (err)
		goto done;

	blame->cb_args.view = view;
	blame->cb_args.lines = blame->lines;
	blame->cb_args.nlines = blame->nlines;
	blame->cb_args.commit_id = got_object_id_dup(commit_id);
	if (blame->cb_args.commit_id == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	blame->cb_args.quit = done;

	blame->thread_args.path = path;
	blame->thread_args.repo = thread_repo;
	blame->thread_args.cb_args = &blame->cb_args;
	blame->thread_args.complete = blame_complete;
	*blame_complete = 0;

done:
	if (blob)
		got_object_blob_close(blob);
	free(obj_id);
	if (err)
		stop_blame(blame);
	return err;
}

static const struct got_error *
open_blame_view(struct tog_view *view, char *path,
    struct got_object_id *commit_id, struct got_reflist_head *refs,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct tog_blame_view_state *s = &view->state.blame;

	SIMPLEQ_INIT(&s->blamed_commits);

	err = got_object_qid_alloc(&s->blamed_commit, commit_id);
	if (err)
		return err;

	SIMPLEQ_INSERT_HEAD(&s->blamed_commits, s->blamed_commit, entry);
	s->first_displayed_line = 1;
	s->last_displayed_line = view->nlines;
	s->selected_line = 1;
	s->blame_complete = 0;
	s->path = path;
	if (s->path == NULL)
		return got_error_from_errno();
	s->repo = repo;
	s->refs = refs;
	s->commit_id = commit_id;
	memset(&s->blame, 0, sizeof(s->blame));

	view->show = show_blame_view;
	view->input = input_blame_view;
	view->close = close_blame_view;

	return run_blame(&s->blame, view, &s->blame_complete,
	    &s->first_displayed_line, &s->last_displayed_line,
	    &s->selected_line, &s->done, &s->eof, s->path,
	    s->blamed_commit->id, s->repo);
}

static const struct got_error *
close_blame_view(struct tog_view *view)
{
	const struct got_error *err = NULL;
	struct tog_blame_view_state *s = &view->state.blame;

	if (s->blame.thread)
		err = stop_blame(&s->blame);

	while (!SIMPLEQ_EMPTY(&s->blamed_commits)) {
		struct got_object_qid *blamed_commit;
		blamed_commit = SIMPLEQ_FIRST(&s->blamed_commits);
		SIMPLEQ_REMOVE_HEAD(&s->blamed_commits, entry);
		got_object_qid_free(blamed_commit);
	}

	free(s->path);

	return err;
}

static const struct got_error *
show_blame_view(struct tog_view *view)
{
	const struct got_error *err = NULL;
	struct tog_blame_view_state *s = &view->state.blame;
	int errcode;

	if (s->blame.thread == NULL) {
		errcode = pthread_create(&s->blame.thread, NULL, blame_thread,
		    &s->blame.thread_args);
		if (errcode)
			return got_error_set_errno(errcode);
	}

	err = draw_blame(view, s->blamed_commit->id, s->blame.f,
	    s->path, s->blame.lines, s->blame.nlines, s->blame_complete,
	    s->selected_line, &s->first_displayed_line,
	    &s->last_displayed_line, &s->eof, view->nlines);

	view_vborder(view);
	return err;
}

static const struct got_error *
input_blame_view(struct tog_view **new_view, struct tog_view **dead_view,
    struct tog_view **focus_view, struct tog_view *view, int ch)
{
	const struct got_error *err = NULL, *thread_err = NULL;
	struct tog_view *diff_view;
	struct tog_blame_view_state *s = &view->state.blame;
	int begin_x = 0;

	switch (ch) {
		case 'q':
			s->done = 1;
			break;
		case 'k':
		case KEY_UP:
			if (s->selected_line > 1)
				s->selected_line--;
			else if (s->selected_line == 1 &&
			    s->first_displayed_line > 1)
				s->first_displayed_line--;
			break;
		case KEY_PPAGE:
			if (s->first_displayed_line == 1) {
				s->selected_line = 1;
				break;
			}
			if (s->first_displayed_line > view->nlines - 2)
				s->first_displayed_line -=
				    (view->nlines - 2);
			else
				s->first_displayed_line = 1;
			break;
		case 'j':
		case KEY_DOWN:
			if (s->selected_line < view->nlines - 2 &&
			    s->first_displayed_line +
			    s->selected_line <= s->blame.nlines)
				s->selected_line++;
			else if (s->last_displayed_line <
			    s->blame.nlines)
				s->first_displayed_line++;
			break;
		case 'b':
		case 'p': {
			struct got_object_id *id = NULL;
			id = get_selected_commit_id(s->blame.lines,
			    s->first_displayed_line, s->selected_line);
			if (id == NULL)
				break;
			if (ch == 'p') {
				struct got_commit_object *commit;
				struct got_object_qid *pid;
				struct got_object_id *blob_id = NULL;
				int obj_type;
				err = got_object_open_as_commit(&commit,
				    s->repo, id);
				if (err)
					break;
				pid = SIMPLEQ_FIRST(
				    got_object_commit_get_parent_ids(commit));
				if (pid == NULL) {
					got_object_commit_close(commit);
					break;
				}
				/* Check if path history ends here. */
				err = got_object_id_by_path(&blob_id, s->repo,
				    pid->id, s->path);
				if (err) {
					if (err->code == GOT_ERR_NO_TREE_ENTRY)
						err = NULL;
					got_object_commit_close(commit);
					break;
				}
				err = got_object_get_type(&obj_type, s->repo,
				    blob_id);
				free(blob_id);
				/* Can't blame non-blob type objects. */
				if (obj_type != GOT_OBJ_TYPE_BLOB) {
					got_object_commit_close(commit);
					break;
				}
				err = got_object_qid_alloc(&s->blamed_commit,
				    pid->id);
				got_object_commit_close(commit);
			} else {
				if (got_object_id_cmp(id,
				    s->blamed_commit->id) == 0)
					break;
				err = got_object_qid_alloc(&s->blamed_commit,
				    id);
			}
			if (err)
				break;
			s->done = 1;
			thread_err = stop_blame(&s->blame);
			s->done = 0;
			if (thread_err)
				break;
			SIMPLEQ_INSERT_HEAD(&s->blamed_commits,
			    s->blamed_commit, entry);
			err = run_blame(&s->blame, view, &s->blame_complete,
			    &s->first_displayed_line, &s->last_displayed_line,
			    &s->selected_line, &s->done, &s->eof,
			    s->path, s->blamed_commit->id, s->repo);
			if (err)
				break;
			break;
		}
		case 'B': {
			struct got_object_qid *first;
			first = SIMPLEQ_FIRST(&s->blamed_commits);
			if (!got_object_id_cmp(first->id, s->commit_id))
				break;
			s->done = 1;
			thread_err = stop_blame(&s->blame);
			s->done = 0;
			if (thread_err)
				break;
			SIMPLEQ_REMOVE_HEAD(&s->blamed_commits, entry);
			got_object_qid_free(s->blamed_commit);
			s->blamed_commit =
			    SIMPLEQ_FIRST(&s->blamed_commits);
			err = run_blame(&s->blame, view, &s->blame_complete,
			    &s->first_displayed_line, &s->last_displayed_line,
			    &s->selected_line, &s->done, &s->eof, s->path,
			    s->blamed_commit->id, s->repo);
			if (err)
				break;
			break;
		}
		case KEY_ENTER:
		case '\r': {
			struct got_object_id *id = NULL;
			struct got_object_qid *pid;
			struct got_commit_object *commit = NULL;
			id = get_selected_commit_id(s->blame.lines,
			    s->first_displayed_line, s->selected_line);
			if (id == NULL)
				break;
			err = got_object_open_as_commit(&commit, s->repo, id);
			if (err)
				break;
			pid = SIMPLEQ_FIRST(
			    got_object_commit_get_parent_ids(commit));
			if (view_is_parent_view(view))
			    begin_x = view_split_begin_x(view->begin_x);
			diff_view = view_open(0, 0, 0, begin_x, TOG_VIEW_DIFF);
			if (diff_view == NULL) {
				got_object_commit_close(commit);
				err = got_error_from_errno();
				break;
			}
			err = open_diff_view(diff_view, pid ? pid->id : NULL,
			    id, NULL, s->refs, s->repo);
			got_object_commit_close(commit);
			if (err) {
				view_close(diff_view);
				break;
			}
			if (view_is_parent_view(view)) {
				err = view_close_child(view);
				if (err)
					break;
				err = view_set_child(view, diff_view);
				if (err) {
					view_close(diff_view);
					break;
				}
				*focus_view = diff_view;
				view->child_focussed = 1;
			} else
				*new_view = diff_view;
			if (err)
				break;
			break;
		}
		case KEY_NPAGE:
		case ' ':
			if (s->last_displayed_line >= s->blame.nlines &&
			    s->selected_line < view->nlines - 2) {
				s->selected_line = MIN(s->blame.nlines,
				    view->nlines - 2);
				break;
			}
			if (s->last_displayed_line + view->nlines - 2
			    <= s->blame.nlines)
				s->first_displayed_line +=
				    view->nlines - 2;
			else
				s->first_displayed_line =
				    s->blame.nlines -
				    (view->nlines - 3);
			break;
		case KEY_RESIZE:
			if (s->selected_line > view->nlines - 2) {
				s->selected_line = MIN(s->blame.nlines,
				    view->nlines - 2);
			}
			break;
		default:
			break;
	}
	return thread_err ? thread_err : err;
}

static const struct got_error *
cmd_blame(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	struct got_reflist_head refs;
	struct got_worktree *worktree = NULL;
	char *path, *cwd = NULL, *repo_path = NULL, *in_repo_path = NULL;
	struct got_object_id *commit_id = NULL;
	char *commit_id_str = NULL;
	int ch;
	struct tog_view *view;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc tty exec sendfd unveil",
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

	init_curses();

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
	} else {
		error = got_object_resolve_id_str(&commit_id, repo,
		    commit_id_str);
	}
	if (error != NULL)
		goto done;

	SIMPLEQ_INIT(&refs);
	error = got_ref_list(&refs, repo);
	if (error)
		goto done;

	view = view_open(0, 0, 0, 0, TOG_VIEW_BLAME);
	if (view == NULL) {
		error = got_error_from_errno();
		goto done;
	}
	error = open_blame_view(view, in_repo_path, commit_id, &refs, repo);
	if (error)
		goto done;
	error = view_loop(view);
done:
	free(repo_path);
	free(cwd);
	free(commit_id);
	if (worktree)
		got_worktree_close(worktree);
	if (repo)
		got_repo_close(repo);
	return error;
}

static const struct got_error *
draw_tree_entries(struct tog_view *view,
    struct got_tree_entry **first_displayed_entry,
    struct got_tree_entry **last_displayed_entry,
    struct got_tree_entry **selected_entry, int *ndisplayed,
    const char *label, int show_ids, const char *parent_path,
    const struct got_tree_entries *entries, int selected, int limit, int isroot)
{
	const struct got_error *err = NULL;
	struct got_tree_entry *te;
	wchar_t *wline;
	int width, n;

	*ndisplayed = 0;

	werase(view->window);

	if (limit == 0)
		return NULL;

	err = format_line(&wline, &width, label, view->ncols);
	if (err)
		return err;
	if (view_needs_focus_indication(view))
		wstandout(view->window);
	waddwstr(view->window, wline);
	if (view_needs_focus_indication(view))
		wstandend(view->window);
	free(wline);
	wline = NULL;
	if (width < view->ncols)
		waddch(view->window, '\n');
	if (--limit <= 0)
		return NULL;
	err = format_line(&wline, &width, parent_path, view->ncols);
	if (err)
		return err;
	waddwstr(view->window, wline);
	free(wline);
	wline = NULL;
	if (width < view->ncols)
		waddch(view->window, '\n');
	if (--limit <= 0)
		return NULL;
	waddch(view->window, '\n');
	if (--limit <= 0)
		return NULL;

	te = SIMPLEQ_FIRST(&entries->head);
	if (*first_displayed_entry == NULL) {
		if (selected == 0) {
			if (view->focussed)
				wstandout(view->window);
			*selected_entry = NULL;
		}
		waddstr(view->window, "  ..\n");	/* parent directory */
		if (selected == 0 && view->focussed)
			wstandend(view->window);
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
		char *line = NULL, *id_str = NULL;

		if (show_ids) {
			err = got_object_id_str(&id_str, te->id);
			if (err)
				return got_error_from_errno();
		}
		if (asprintf(&line, "%s  %s%s", id_str ? id_str : "",
		    te->name, S_ISDIR(te->mode) ? "/" :
		    ((te->mode & S_IXUSR) ? "*" : "")) == -1) {
			free(id_str);
			return got_error_from_errno();
		}
		free(id_str);
		err = format_line(&wline, &width, line, view->ncols);
		if (err) {
			free(line);
			break;
		}
		if (n == selected) {
			if (view->focussed)
				wstandout(view->window);
			*selected_entry = te;
		}
		waddwstr(view->window, wline);
		if (width < view->ncols)
			waddch(view->window, '\n');
		if (n == selected && view->focussed)
			wstandend(view->window);
		free(line);
		free(wline);
		wline = NULL;
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

static int
tree_scroll_down(struct got_tree_entry **first_displayed_entry, int maxscroll,
	struct got_tree_entry *last_displayed_entry,
	const struct got_tree_entries *entries)
{
	struct got_tree_entry *next, *last;
	int n = 0;

	if (*first_displayed_entry)
		next = SIMPLEQ_NEXT(*first_displayed_entry, entry);
	else
		next = SIMPLEQ_FIRST(&entries->head);
	last = last_displayed_entry;
	while (next && last && n++ < maxscroll) {
		last = SIMPLEQ_NEXT(last, entry);
		if (last) {
			*first_displayed_entry = next;
			next = SIMPLEQ_NEXT(next, entry);
		}
	}
	return n;
}

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
blame_tree_entry(struct tog_view **new_view, int begin_x,
    struct got_tree_entry *te, struct tog_parent_trees *parents,
    struct got_object_id *commit_id, struct got_reflist_head *refs,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *path;
	struct tog_view *blame_view;

	err = tree_entry_path(&path, parents, te);
	if (err)
		return err;

	blame_view = view_open(0, 0, 0, begin_x, TOG_VIEW_BLAME);
	if (blame_view == NULL)
		return got_error_from_errno();

	err = open_blame_view(blame_view, path, commit_id, refs, repo);
	if (err) {
		view_close(blame_view);
		free(path);
	} else
		*new_view = blame_view;
	return err;
}

static const struct got_error *
log_tree_entry(struct tog_view **new_view, int begin_x,
    struct got_tree_entry *te, struct tog_parent_trees *parents,
    struct got_object_id *commit_id, struct got_reflist_head *refs,
    struct got_repository *repo)
{
	struct tog_view *log_view;
	const struct got_error *err = NULL;
	char *path;

	log_view = view_open(0, 0, 0, begin_x, TOG_VIEW_LOG);
	if (log_view == NULL)
		return got_error_from_errno();

	err = tree_entry_path(&path, parents, te);
	if (err)
		return err;

	err = open_log_view(log_view, commit_id, refs, repo, path, 0);
	if (err)
		view_close(log_view);
	else
		*new_view = log_view;
	free(path);
	return err;
}

static const struct got_error *
open_tree_view(struct tog_view *view, struct got_tree_object *root,
    struct got_object_id *commit_id, struct got_reflist_head *refs,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *commit_id_str = NULL;
	struct tog_tree_view_state *s = &view->state.tree;

	TAILQ_INIT(&s->parents);

	err = got_object_id_str(&commit_id_str, commit_id);
	if (err != NULL)
		goto done;

	if (asprintf(&s->tree_label, "commit %s", commit_id_str) == -1) {
		err = got_error_from_errno();
		goto done;
	}

	s->root = s->tree = root;
	s->entries = got_object_tree_get_entries(root);
	s->first_displayed_entry = SIMPLEQ_FIRST(&s->entries->head);
	s->commit_id = got_object_id_dup(commit_id);
	if (s->commit_id == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	s->refs = refs;
	s->repo = repo;

	view->show = show_tree_view;
	view->input = input_tree_view;
	view->close = close_tree_view;
done:
	free(commit_id_str);
	if (err) {
		free(s->tree_label);
		s->tree_label = NULL;
	}
	return err;
}

static const struct got_error *
close_tree_view(struct tog_view *view)
{
	struct tog_tree_view_state *s = &view->state.tree;

	free(s->tree_label);
	s->tree_label = NULL;
	free(s->commit_id);
	s->commit_id = NULL;
	while (!TAILQ_EMPTY(&s->parents)) {
		struct tog_parent_tree *parent;
		parent = TAILQ_FIRST(&s->parents);
		TAILQ_REMOVE(&s->parents, parent, entry);
		free(parent);

	}
	if (s->tree != s->root)
		got_object_tree_close(s->tree);
	got_object_tree_close(s->root);

	return NULL;
}

static const struct got_error *
show_tree_view(struct tog_view *view)
{
	const struct got_error *err = NULL;
	struct tog_tree_view_state *s = &view->state.tree;
	char *parent_path;

	err = tree_entry_path(&parent_path, &s->parents, NULL);
	if (err)
		return err;

	err = draw_tree_entries(view, &s->first_displayed_entry,
	    &s->last_displayed_entry, &s->selected_entry,
	    &s->ndisplayed, s->tree_label, s->show_ids, parent_path,
	    s->entries, s->selected, view->nlines, s->tree == s->root);
	free(parent_path);

	view_vborder(view);
	return err;
}

static const struct got_error *
input_tree_view(struct tog_view **new_view, struct tog_view **dead_view,
    struct tog_view **focus_view, struct tog_view *view, int ch)
{
	const struct got_error *err = NULL;
	struct tog_tree_view_state *s = &view->state.tree;
	struct tog_view *log_view;
	int begin_x = 0, nscrolled;

	switch (ch) {
		case 'i':
			s->show_ids = !s->show_ids;
			break;
		case 'l':
			if (!s->selected_entry)
				break;
			if (view_is_parent_view(view))
				begin_x = view_split_begin_x(view->begin_x);
			err = log_tree_entry(&log_view, begin_x,
			    s->selected_entry, &s->parents,
			    s->commit_id, s->refs, s->repo);
			if (view_is_parent_view(view)) {
				err = view_close_child(view);
				if (err)
					return err;
				err = view_set_child(view, log_view);
				if (err) {
					view_close(log_view);
					break;
				}
				*focus_view = log_view;
				view->child_focussed = 1;
			} else
				*new_view = log_view;
			break;
		case 'k':
		case KEY_UP:
			if (s->selected > 0) {
				s->selected--;
				if (s->selected == 0)
					break;
			}
			if (s->selected > 0)
				break;
			tree_scroll_up(&s->first_displayed_entry, 1,
			    s->entries, s->tree == s->root);
			break;
		case KEY_PPAGE:
			tree_scroll_up(&s->first_displayed_entry,
			    MAX(0, view->nlines - 4 - s->selected), s->entries,
			    s->tree == s->root);
			s->selected = 0;
			if (SIMPLEQ_FIRST(&s->entries->head) ==
			    s->first_displayed_entry && s->tree != s->root)
				s->first_displayed_entry = NULL;
			break;
		case 'j':
		case KEY_DOWN:
			if (s->selected < s->ndisplayed - 1) {
				s->selected++;
				break;
			}
			if (SIMPLEQ_NEXT(s->last_displayed_entry, entry)
			    == NULL) {
				/* can't scroll any further */
				break;
			}
			tree_scroll_down(&s->first_displayed_entry, 1,
			    s->last_displayed_entry, s->entries);
			break;
		case KEY_NPAGE:
			if (SIMPLEQ_NEXT(s->last_displayed_entry, entry)
			    == NULL) {
				/* can't scroll any further; move cursor down */
				if (s->selected < s->ndisplayed - 1)
					s->selected = s->ndisplayed - 1;
				break;
			}
			nscrolled = tree_scroll_down(&s->first_displayed_entry,
			    view->nlines, s->last_displayed_entry, s->entries);
			if (nscrolled < view->nlines) {
				int ndisplayed = 0;
				struct got_tree_entry *te;
				te = s->first_displayed_entry;
				do {
					ndisplayed++;
					te = SIMPLEQ_NEXT(te, entry);
				} while (te);
				s->selected = ndisplayed - 1;
			}
			break;
		case KEY_ENTER:
		case '\r':
			if (s->selected_entry == NULL) {
				struct tog_parent_tree *parent;
		case KEY_BACKSPACE:
				/* user selected '..' */
				if (s->tree == s->root)
					break;
				parent = TAILQ_FIRST(&s->parents);
				TAILQ_REMOVE(&s->parents, parent,
				    entry);
				got_object_tree_close(s->tree);
				s->tree = parent->tree;
				s->entries =
				    got_object_tree_get_entries(s->tree);
				s->first_displayed_entry =
				    parent->first_displayed_entry;
				s->selected_entry =
				    parent->selected_entry;
				s->selected = parent->selected;
				free(parent);
			} else if (S_ISDIR(s->selected_entry->mode)) {
				struct tog_parent_tree *parent;
				struct got_tree_object *child;
				err = got_object_open_as_tree(&child,
				    s->repo, s->selected_entry->id);
				if (err)
					break;
				parent = calloc(1, sizeof(*parent));
				if (parent == NULL) {
					err = got_error_from_errno();
					break;
				}
				parent->tree = s->tree;
				parent->first_displayed_entry =
				   s->first_displayed_entry;
				parent->selected_entry = s->selected_entry;
				parent->selected = s->selected;
				TAILQ_INSERT_HEAD(&s->parents, parent, entry);
				s->tree = child;
				s->entries =
				    got_object_tree_get_entries(s->tree);
				s->selected = 0;
				s->first_displayed_entry = NULL;
			} else if (S_ISREG(s->selected_entry->mode)) {
				struct tog_view *blame_view;
				int begin_x = view_is_parent_view(view) ?
				    view_split_begin_x(view->begin_x) : 0;

				err = blame_tree_entry(&blame_view, begin_x,
				    s->selected_entry, &s->parents,
				    s->commit_id, s->refs, s->repo);
				if (err)
					break;
				if (view_is_parent_view(view)) {
					err = view_close_child(view);
					if (err)
						return err;
					err = view_set_child(view, blame_view);
					if (err) {
						view_close(blame_view);
						break;
					}
					*focus_view = blame_view;
					view->child_focussed = 1;
				} else
					*new_view = blame_view;
			}
			break;
		case KEY_RESIZE:
			if (s->selected > view->nlines)
				s->selected = s->ndisplayed - 1;
			break;
		default:
			break;
	}

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
	struct got_reflist_head refs;
	char *repo_path = NULL;
	struct got_object_id *commit_id = NULL;
	char *commit_id_arg = NULL;
	struct got_commit_object *commit = NULL;
	struct got_tree_object *tree = NULL;
	int ch;
	struct tog_view *view;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc tty exec sendfd unveil",
	    NULL) == -1)
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
		struct got_worktree *worktree;
		char *cwd = getcwd(NULL, 0);
		if (cwd == NULL)
			return got_error_from_errno();
		error = got_worktree_open(&worktree, cwd);
		if (error && error->code != GOT_ERR_NOT_WORKTREE)
			goto done;
		if (worktree) {
			free(cwd);
			repo_path =
			    strdup(got_worktree_get_repo_path(worktree));
			got_worktree_close(worktree);
		} else
			repo_path = cwd;
		if (repo_path == NULL) {
			error = got_error_from_errno();
			goto done;
		}
	} else if (argc == 1) {
		repo_path = realpath(argv[0], NULL);
		if (repo_path == NULL)
			return got_error_from_errno();
	} else
		usage_log();

	init_curses();

	error = apply_unveil(repo_path, NULL);
	if (error)
		goto done;

	error = got_repo_open(&repo, repo_path);
	if (error != NULL)
		goto done;

	if (commit_id_arg == NULL)
		error = get_head_commit_id(&commit_id, repo);
	else
		error = got_object_resolve_id_str(&commit_id, repo,
		    commit_id_arg);
	if (error != NULL)
		goto done;

	error = got_object_open_as_commit(&commit, repo, commit_id);
	if (error != NULL)
		goto done;

	error = got_object_open_as_tree(&tree, repo,
	    got_object_commit_get_tree_id(commit));
	if (error != NULL)
		goto done;

	SIMPLEQ_INIT(&refs);
	error = got_ref_list(&refs, repo);
	if (error)
		goto done;

	view = view_open(0, 0, 0, 0, TOG_VIEW_TREE);
	if (view == NULL) {
		error = got_error_from_errno();
		goto done;
	}
	error = open_tree_view(view, tree, commit_id, &refs, repo);
	if (error)
		goto done;
	error = view_loop(view);
done:
	free(repo_path);
	free(commit_id);
	if (commit)
		got_object_commit_close(commit);
	if (tree)
		got_object_tree_close(tree);
	if (repo)
		got_repo_close(repo);
	return error;
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
