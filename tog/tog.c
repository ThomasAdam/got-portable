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

enum tog_view_type {
	TOG_VIEW_DIFF,
	TOG_VIEW_LOG,
	TOG_VIEW_BLAME,
	TOG_VIEW_TREE
};

struct tog_diff_view_state {
	struct got_object_id *id1, *id2;
	FILE *f;
	int first_displayed_line;
	int last_displayed_line;
	int eof;
};

struct commit_queue_entry {
	TAILQ_ENTRY(commit_queue_entry) entry;
	struct got_object_id *id;
	struct got_commit_object *commit;
};
TAILQ_HEAD(commit_queue_head, commit_queue_entry);
struct commit_queue {
	int ncommits;
	struct commit_queue_head head;
};

struct tog_log_view_state {
	struct got_commit_graph *graph;
	struct commit_queue commits;
	struct commit_queue_entry *first_displayed_entry;
	struct commit_queue_entry *last_displayed_entry;
	struct commit_queue_entry *selected_entry;
	int selected;
	char *in_repo_path;
	struct got_repository *repo;
};

struct tog_blame_cb_args {
	pthread_mutex_t *mutex;
	struct tog_blame_line *lines; /* one per line */
	int nlines;

	struct tog_view *view;
	struct got_object_id *commit_id;
	FILE *f;
	const char *path;
	int *first_displayed_line;
	int *last_displayed_line;
	int *selected_line;
	int *quit;
	int *eof;
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
	size_t nlines;
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
	pthread_mutex_t mutex;
	struct got_object_id_queue blamed_commits;
	struct got_object_qid *blamed_commit;
	char *path;
	struct got_repository *repo;
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
	int nentries, ndisplayed, selected, show_ids;
	struct tog_parent_trees parents;
	struct got_object_id *commit_id;
	struct got_repository *repo;
};

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
	    struct tog_view **, struct tog_view *, int);
	const struct got_error *(*set_child)(struct tog_view *,
	    struct tog_view *);
	const struct got_error *(*close)(struct tog_view *);
};

static const struct got_error *open_diff_view(struct tog_view *,
    struct got_object *, struct got_object *, struct got_repository *);
static const struct got_error *show_diff_view(struct tog_view *);
static const struct got_error *input_diff_view(struct tog_view **,
    struct tog_view **, struct tog_view *, int);
static const struct got_error* close_diff_view(struct tog_view *);

static const struct got_error *open_log_view(struct tog_view *,
    struct got_object_id *, struct got_repository *, const char *);
static const struct got_error * show_log_view(struct tog_view *);
static const struct got_error *input_log_view(struct tog_view **,
    struct tog_view **, struct tog_view *, int);
static const struct got_error *close_log_view(struct tog_view *);
static const struct got_error* set_child_log_view(struct tog_view *,
    struct tog_view *);

static const struct got_error *open_blame_view(struct tog_view *, char *,
    struct got_object_id *, struct got_repository *);
static const struct got_error *show_blame_view(struct tog_view *);
static const struct got_error *input_blame_view(struct tog_view **,
    struct tog_view **, struct tog_view *, int);
static const struct got_error *close_blame_view(struct tog_view *);

static const struct got_error *open_tree_view(struct tog_view *,
    struct got_tree_object *, struct got_object_id *, struct got_repository *);
static const struct got_error *show_tree_view(struct tog_view *);
static const struct got_error *input_tree_view(struct tog_view **,
    struct tog_view **, struct tog_view *, int);
static const struct got_error *close_tree_view(struct tog_view *);

static const struct got_error *
view_close(struct tog_view *view)
{
	const struct got_error *err = NULL;

	if (view->child)
		view->child->parent = NULL;
	if (view->parent)
		view->parent->child = NULL;
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
    struct tog_view *parent, enum tog_view_type type)
{
	struct tog_view *view = calloc(1, sizeof(*view));

	if (view == NULL)
		return NULL;

	if (begin_x == 0 && parent && parent->ncols - 80 > 10)
		begin_x = parent->ncols - 80;

	view->parent = parent;
	if (parent)
		parent->child = view;
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
	if (view->panel == NULL) {
		view_close(view);
		return NULL;
	}

	keypad(view->window, TRUE);
	return view;
}

static const struct got_error *
view_show(struct tog_view *view)
{
	const struct got_error *err;

	if (view->parent) {
		err = view->parent->show(view->parent);
		if (err)
			return err;
		show_panel(view->parent->panel);
	}

	err = view->show(view);
	if (err)
		return err;
	show_panel(view->panel);

	if (view->child && view->child->begin_x > view->begin_x) {
		err = view->child->show(view->child);
		if (err)
			return err;
		show_panel(view->child->panel);
	}

	update_panels();
	doupdate();

	return err;
}

static const struct got_error *
view_resize(struct tog_view *view)
{
	int nlines, ncols;

	while (view) {
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
		replace_panel(view->panel, view->window);

		view->nlines = nlines;
		view->ncols = ncols;
		view->lines = LINES;
		view->cols = COLS;

		view = view->parent;
	}

	return NULL;
}

static const struct got_error *
view_input(struct tog_view **new, struct tog_view **dead,
    struct tog_view **focus, int *done, struct tog_view *view,
    struct tog_view_list_head *views)
{
	const struct got_error *err = NULL;
	struct tog_view *next, *prev;
	int ch;

	*new = NULL;
	*dead = NULL;

	nodelay(stdscr, FALSE);
	ch = wgetch(view->window);
	nodelay(stdscr, TRUE);
	switch (ch) {
		case ERR:
			break;
		case '\t':
			next = TAILQ_NEXT(view, entry);
			if (next)
				*focus = next;
			else
				*focus = TAILQ_FIRST(views);
			view->focussed = 0;
			(*focus)->focussed = 1;
			break;
		case KEY_BACKSPACE:
			prev = TAILQ_PREV(view, tog_view_list_head, entry);
			if (prev)
				*focus = prev;
			else
				*focus = TAILQ_LAST(views, tog_view_list_head);
			view->focussed = 0;
			(*focus)->focussed = 1;
			break;
		case 'q':
			err = view->input(new, dead, view, ch);
			*dead = view;
			break;
		case 'Q':
			*done = 1;
			break;
		case KEY_RESIZE:
			err = view_resize(view);
			if (err)
				return err;
			err = view->input(new, dead, view, ch);
			break;
		default:
			err = view->input(new, dead, view, ch);
			break;
	}

	return err;
}

static const struct got_error *
view_set_child(struct tog_view *view, struct tog_view *child)
{
	const struct got_error *err;

	if (view->set_child) {
		err = view->set_child(view, child);
		if (err)
			return err;
	}

	view->child = child;
	return NULL;
}

void
view_vborder(struct tog_view *view)
{
	if (view->child == NULL)
		return;

	mvwvline(view->window, view->begin_y, view->child->begin_x - 1,
	    got_locale_is_utf8() ? ACS_VLINE : '|', view->nlines);
}

int
view_needs_focus_indication(struct tog_view *view)
{
	if (!view->focussed)
		return 0;

	if (view->child && view->child->begin_x > view->begin_x)
		return 1;

	if (view->parent && view->begin_x > view->parent->begin_x)
		return 1;

	return 0;
}

static const struct got_error *
view_loop(struct tog_view *view)
{
	const struct got_error *err = NULL;
	struct tog_view_list_head views;
	struct tog_view *new_view, *dead_view;
	int done = 0;

	TAILQ_INIT(&views);
	TAILQ_INSERT_HEAD(&views, view, entry);

	view->focussed = 1;
	while (!TAILQ_EMPTY(&views) && !done) {
		err = view_show(view);
		if (err)
			break;
		err = view_input(&new_view, &dead_view, &view, &done,
		    view, &views);
		if (err)
			break;
		if (dead_view) {
			struct tog_view *v, *t;
			TAILQ_REMOVE(&views, dead_view, entry);
			TAILQ_FOREACH_SAFE(v, &views, entry, t) {
				if (v->parent == dead_view) {
					TAILQ_REMOVE(&views, v, entry);
					err = view_close(v);
					if (err)
						goto done;
				}
			}
			if (dead_view->parent)
				view = dead_view->parent;
			else
				view = TAILQ_LAST(&views, tog_view_list_head);
			if (view)
				view->focussed = 1;
			err = view_close(dead_view);
			if (err)
				goto done;
		}
		if (new_view) {
			view->focussed = 0;
			/* TODO: de-duplicate! */
			TAILQ_INSERT_TAIL(&views, new_view, entry);
			if (new_view->parent) {
				err = view_set_child(new_view->parent, new_view);
				if (err)
					goto done;
				new_view->parent->focussed = 0;
			}
			view = new_view;
			view->focussed = 1;
		}
	}
done:
	while (!TAILQ_EMPTY(&views)) {
		view = TAILQ_FIRST(&views);
		TAILQ_REMOVE(&views, view, entry);
		view_close(view);
	}
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

static const struct got_error *
draw_commit(struct tog_view *view, struct got_commit_object *commit,
    struct got_object_id *id)
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

	if (strftime(datebuf, sizeof(datebuf), "%g/%m/%d ",
	    &commit->tm_committer) >= sizeof(datebuf))
		return got_error(GOT_ERR_NO_SPACE);

	if (avail < date_display_cols)
		limit = MIN(sizeof(datebuf) - 1, avail);
	else
		limit = MIN(date_display_cols, sizeof(datebuf) - 1);
	waddnstr(view->window, datebuf, limit);
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
	waddwstr(view->window, wauthor);
	col += author_width;
	while (col <= avail && author_width < author_display_cols + 1) {
		waddch(view->window, ' ');
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
    struct got_object_id *start_id, int minqueue, int init,
    struct got_repository *repo, const char *path)
{
	const struct got_error *err = NULL;
	struct got_object_id *id;
	struct commit_queue_entry *entry;
	int nqueued = 0, found_obj = 0;
	int is_root_path = strcmp(path, "/") == 0;

	err = got_commit_graph_iter_start(graph, start_id, repo);
	if (err)
		return err;

	entry = TAILQ_LAST(&commits->head, commit_queue_head);
	if (entry && got_object_id_cmp(entry->id, start_id) == 0) {
		/* Start ID's commit is already on the queue; skip over it. */
		err = got_commit_graph_iter_next(&id, graph);
		if (err && err->code != GOT_ERR_ITER_NEED_MORE)
			return err;

		err = got_commit_graph_fetch_commits(graph, 1, repo);
		if (err)
			return err;
	}

	while (1) {
		struct got_commit_object *commit;

		err = got_commit_graph_iter_next(&id, graph);
		if (err) {
			if (err->code != GOT_ERR_ITER_NEED_MORE)
				break;
			if (nqueued >= minqueue) {
				err = NULL;
				break;
			}
			err = got_commit_graph_fetch_commits(graph, 1, repo);
			if (err)
				return err;
			continue;
		}
		if (id == NULL)
			break;

		err = got_object_open_as_commit(&commit, repo, id);
		if (err)
			break;

		if (!is_root_path) {
			struct got_object_id *obj_id = NULL;
			struct got_object_qid *pid;
			int changed = 0;

			err = got_object_id_by_path(&obj_id, repo, id, path);
			if (err) {
				got_object_commit_close(commit);
				if (err->code == GOT_ERR_NO_OBJ &&
				    (found_obj || !init)) {
					/* History stops here. */
					err = got_error(GOT_ERR_ITER_COMPLETED);
				}
				break;
			}
			found_obj = 1;

			pid = SIMPLEQ_FIRST(&commit->parent_ids);
			if (pid != NULL) {
				struct got_object_id *pobj_id;
				err = got_object_id_by_path(&pobj_id, repo,
				    pid->id, path);
				if (err) {
					if (err->code != GOT_ERR_NO_OBJ) {
						got_object_commit_close(commit);
						free(obj_id);
						break;
					}
					err = NULL;
					changed = 1;
				} else {
					changed = (got_object_id_cmp(obj_id,
					    pobj_id) != 0);
				}
				free(pobj_id);
			}
			free(obj_id);
			if (!changed) {
				got_object_commit_close(commit);
				continue;
			}
		}

		entry = alloc_commit_queue_entry(commit, id);
		if (entry == NULL) {
			err = got_error_from_errno();
			break;
		}
		TAILQ_INSERT_TAIL(&commits->head, entry, entry);
		nqueued++;
		commits->ncommits++;
	}

	return err;
}

static const struct got_error *
fetch_next_commit(struct commit_queue_entry **pentry,
    struct commit_queue_entry *entry, struct commit_queue *commits,
    struct got_commit_graph *graph, struct got_repository *repo,
    const char *path)
{
	const struct got_error *err = NULL;

	*pentry = NULL;

	err = queue_commits(graph, commits, entry->id, 1, 0, repo, path);
	if (err)
		return err;

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
draw_commits(struct tog_view *view, struct commit_queue_entry **last,
    struct commit_queue_entry **selected, struct commit_queue_entry *first,
    struct commit_queue *commits, int selected_idx, int limit,
    struct got_commit_graph *graph, struct got_repository *repo,
    const char *path)
{
	const struct got_error *err = NULL;
	struct commit_queue_entry *entry;
	int ncommits, width;
	char *id_str, *header;
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

	err = got_object_id_str(&id_str, (*selected)->id);
	if (err)
		return err;

	if (path && strcmp(path, "/") != 0) {
		if (asprintf(&header, "commit: %s [%s]", id_str, path) == -1) {
			err = got_error_from_errno();
			free(id_str);
			return err;
		}
	} else if (asprintf(&header, "commit: %s", id_str) == -1) {
		err = got_error_from_errno();
		free(id_str);
		return err;
	}
	free(id_str);
	err = format_line(&wline, &width, header, view->ncols);
	if (err) {
		free(header);
		return err;
	}
	free(header);

	werase(view->window);

	if (view_needs_focus_indication(view))
		wstandout(view->window);
	waddwstr(view->window, wline);
	if (view_needs_focus_indication(view))
		wstandend(view->window);
	if (width < view->ncols)
		waddch(view->window, '\n');
	free(wline);
	if (limit <= 1)
		return NULL;

	entry = first;
	*last = first;
	ncommits = 0;
	while (entry) {
		if (ncommits >= limit - 1)
			break;
		if (ncommits == selected_idx)
			wstandout(view->window);
		err = draw_commit(view, entry->commit, entry->id);
		if (ncommits == selected_idx)
			wstandend(view->window);
		if (err)
			break;
		ncommits++;
		*last = entry;
		if (entry == TAILQ_LAST(&commits->head, commit_queue_head)) {
			err = queue_commits(graph, commits, entry->id, 1,
			    0, repo, path);
			if (err) {
				if (err->code != GOT_ERR_ITER_COMPLETED)
					return err;
				err = NULL;
			}
		}
		entry = TAILQ_NEXT(entry, entry);
	}

	view_vborder(view);

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
scroll_down(struct commit_queue_entry **first_displayed_entry, int maxscroll,
    struct commit_queue_entry *last_displayed_entry,
    struct commit_queue *commits, struct got_commit_graph *graph,
    struct got_repository *repo, const char *path)
{
	const struct got_error *err = NULL;
	struct commit_queue_entry *pentry;
	int nscrolled = 0;

	do {
		pentry = TAILQ_NEXT(last_displayed_entry, entry);
		if (pentry == NULL) {
			err = fetch_next_commit(&pentry, last_displayed_entry,
			    commits, graph, repo, path);
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

static const struct got_error *
show_commit(struct tog_view **new_view, struct tog_view *parent_view,
    struct commit_queue_entry *entry, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_object *obj1 = NULL, *obj2 = NULL;
	struct got_object_qid *parent_id;
	struct tog_view *diff_view;

	err = got_object_open(&obj2, repo, entry->id);
	if (err)
		return err;

	parent_id = SIMPLEQ_FIRST(&entry->commit->parent_ids);
	if (parent_id) {
		err = got_object_open(&obj1, repo, parent_id->id);
		if (err)
			goto done;
	}

	diff_view = view_open(0, 0, 0, 0, parent_view, TOG_VIEW_DIFF);
	if (diff_view == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	err = open_diff_view(diff_view, obj1, obj2, repo);
	if (err == NULL)
		*new_view = diff_view;
done:
	if (obj1)
		got_object_close(obj1);
	if (obj2)
		got_object_close(obj2);
	return err;
}

static const struct got_error *
browse_commit(struct tog_view **new_view, struct tog_view *parent_view,
    struct commit_queue_entry *entry, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_tree_object *tree;
	struct tog_view *tree_view;

	err = got_object_open_as_tree(&tree, repo, entry->commit->tree_id);
	if (err)
		return err;

	tree_view = view_open(0, 0, 0, 0, parent_view, TOG_VIEW_TREE);
	if (tree_view == NULL)
		return got_error_from_errno();

	err = open_tree_view(tree_view, tree, entry->id, repo);
	if (err)
		got_object_tree_close(tree);
	else
		*new_view = tree_view;
	return err;
}

static const struct got_error *
set_child_log_view(struct tog_view *view, struct tog_view *child)
{
	struct tog_log_view_state *s = &view->state.log;
	struct tog_diff_view_state *ds;
	struct commit_queue_entry *commit, *child_entry = NULL;
	int selected_idx = 0;

	if (child->type != TOG_VIEW_DIFF)
		return NULL;
	ds = &child->state.diff;

	TAILQ_FOREACH(commit, &s->commits.head, entry) {
		if (got_object_id_cmp(commit->id, ds->id2) == 0) {
			child_entry = commit;
			break;
		}
	}
	if (child_entry == NULL)
		return NULL;

	commit = s->first_displayed_entry;
	while (commit) {
		if (got_object_id_cmp(commit->id, child_entry->id) == 0) {
			s->selected_entry = child_entry;
			s->selected = selected_idx;
			break;
		}
		if (commit == s->last_displayed_entry)
			break;
		selected_idx++;
		commit = TAILQ_NEXT(commit, entry);
	}

	return show_log_view(view);
}

static const struct got_error *
open_log_view(struct tog_view *view, struct got_object_id *start_id,
    struct got_repository *repo, const char *path)
{
	const struct got_error *err = NULL;
	struct got_object_id *head_id = NULL;
	int nfetched;
	struct tog_log_view_state *s = &view->state.log;

	err = got_repo_map_path(&s->in_repo_path, repo, path);
	if (err != NULL)
		goto done;

	err = get_head_commit_id(&head_id, repo);
	if (err)
		return err;

	/* The graph contains all commits. */
	err = got_commit_graph_open(&s->graph, head_id, "/", 0, repo);
	if (err)
		goto done;
	/* The commit queue contains a subset of commits filtered by path. */
	TAILQ_INIT(&s->commits.head);
	s->commits.ncommits = 0;

	/* Populate commit graph with a sufficient number of commits. */
	err = got_commit_graph_fetch_commits_up_to(&nfetched, s->graph,
	    start_id, repo);
	if (err)
		goto done;

	/*
	 * Open the initial batch of commits, sorted in commit graph order.
	 * We keep all commits open throughout the lifetime of the log view
	 * in order to avoid having to re-fetch commits from disk while
	 * updating the display.
	 */
	err = queue_commits(s->graph, &s->commits, start_id, view->nlines, 1,
	    repo, s->in_repo_path);
	if (err) {
		if (err->code != GOT_ERR_ITER_COMPLETED)
			goto done;
		err = NULL;
	}

	s->first_displayed_entry =
	    TAILQ_FIRST(&s->commits.head);
	s->selected_entry = s->first_displayed_entry;
	s->repo = repo;

	view->show = show_log_view;
	view->input = input_log_view;
	view->close = close_log_view;
	view->set_child = set_child_log_view;
done:
	free(head_id);
	return err;
}

static const struct got_error *
close_log_view(struct tog_view *view)
{
	struct tog_log_view_state *s = &view->state.log;

	if (s->graph)
		got_commit_graph_close(s->graph);
	free_commits(&s->commits);
	free(s->in_repo_path);
	return NULL;
}

static const struct got_error *
update_diff_child_view(struct tog_view *parent,
    struct commit_queue_entry *selected_entry, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct tog_diff_view_state *ds;
	struct got_object *obj1 = NULL, *obj2 = NULL;
	struct got_object_qid *parent_id;
	struct tog_view *child_view = parent->child;

	if (child_view == NULL)
		return NULL;
	if (child_view->type != TOG_VIEW_DIFF)
		return NULL;
	ds = &child_view->state.diff;
	if (got_object_id_cmp(ds->id2, selected_entry->id) == 0)
		return NULL;

	err = got_object_open(&obj2, repo, selected_entry->id);
	if (err)
		return err;

	parent_id = SIMPLEQ_FIRST(&selected_entry->commit->parent_ids);
	if (parent_id) {
		err = got_object_open(&obj1, repo, parent_id->id);
		if (err)
			goto done;
	}

	err = close_diff_view(child_view);
	if (err)
		goto done;

	err = open_diff_view(child_view, obj1, obj2, repo);
	if (err)
		goto done;
done:
	if (obj1)
		got_object_close(obj1);
	if (obj2)
		got_object_close(obj2);
	return err;
}

static const struct got_error *
show_log_view(struct tog_view *view)
{
	const struct got_error *err = NULL;
	struct tog_log_view_state *s = &view->state.log;

	err = draw_commits(view, &s->last_displayed_entry,
	    &s->selected_entry, s->first_displayed_entry,
	    &s->commits, s->selected, view->nlines, s->graph,
	    s->repo, s->in_repo_path);
	if (err)
		return err;

	return update_diff_child_view(view, s->selected_entry, s->repo);
}

static const struct got_error *
input_log_view(struct tog_view **new_view, struct tog_view **dead_view,
    struct tog_view *view, int ch)
{
	const struct got_error *err = NULL;
	struct tog_log_view_state *s = &view->state.log;

	switch (ch) {
		case 'k':
		case KEY_UP:
		case '[':
			if (s->selected > 0)
				s->selected--;
			if (s->selected > 0)
				break;
			scroll_up(&s->first_displayed_entry, 1,
			    &s->commits);
			break;
		case KEY_PPAGE:
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
		case ']':
			if (s->selected < MIN(view->nlines - 2,
			    s->commits.ncommits - 1)) {
				s->selected++;
				break;
			}
			err = scroll_down(&s->first_displayed_entry, 1,
			    s->last_displayed_entry, &s->commits,
			    s->graph, s->repo, s->in_repo_path);
			if (err) {
				if (err->code != GOT_ERR_ITER_COMPLETED)
					break;
				err = NULL;
			}
			break;
		case KEY_NPAGE: {
			struct commit_queue_entry *first;
			first = s->first_displayed_entry;
			err = scroll_down(&s->first_displayed_entry,
			    view->nlines, s->last_displayed_entry,
			    &s->commits, s->graph, s->repo,
			    s->in_repo_path);
			if (err == NULL)
				break;
			if (err->code != GOT_ERR_ITER_COMPLETED)
				break;
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
			err = show_commit(new_view, view, s->selected_entry,
			    s->repo);
			break;
		case 't':
			err = browse_commit(new_view, view, s->selected_entry,
			    s->repo);
			break;
		default:
			break;
	}

	return err;
}

static const struct got_error *
cmd_log(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	struct got_object_id *start_id = NULL;
	char *path = NULL, *repo_path = NULL, *cwd = NULL;
	char *start_commit = NULL;
	int ch;
	struct tog_view *view;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc tty exec sendfd", NULL)
	    == -1)
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
		error = get_head_commit_id(&start_id, repo);
		if (error != NULL)
			goto done;
	} else {
		struct got_object *obj;
		error = got_object_open_by_id_str(&obj, repo, start_commit);
		if (error == NULL) {
			start_id = got_object_id_dup(got_object_get_id(obj));
			if (start_id == NULL)
				error = got_error_from_errno();
				goto done;
		}
	}
	if (error != NULL)
		goto done;

	view = view_open(0, 0, 0, 0, NULL, TOG_VIEW_LOG);
	if (view == NULL) {
		error = got_error_from_errno();
		goto done;
	}
	error = open_log_view(view, start_id, repo, path);
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

static const struct got_error *
open_diff_view(struct tog_view *view, struct got_object *obj1,
    struct got_object *obj2, struct got_repository *repo)
{
	const struct got_error *err;
	FILE *f;

	if (obj1 != NULL && obj2 != NULL &&
	    got_object_get_type(obj1) != got_object_get_type(obj2))
		return got_error(GOT_ERR_OBJ_TYPE);

	f = got_opentemp();
	if (f == NULL)
		return got_error_from_errno();

	switch (got_object_get_type(obj1 ? obj1 : obj2)) {
	case GOT_OBJ_TYPE_BLOB:
		err = got_diff_objects_as_blobs(obj1, obj2, NULL, NULL,
		    repo, f);
		break;
	case GOT_OBJ_TYPE_TREE:
		err = got_diff_objects_as_trees(obj1, obj2, "", "", repo, f);
		break;
	case GOT_OBJ_TYPE_COMMIT:
		err = got_diff_objects_as_commits(obj1, obj2, repo, f);
		break;
	default:
		return got_error(GOT_ERR_OBJ_TYPE);
	}

	fflush(f);

	view->state.diff.id1 = obj1 ? got_object_get_id(obj1) : NULL;
	view->state.diff.id2 = got_object_get_id(obj2);
	view->state.diff.f = f;
	view->state.diff.first_displayed_line = 1;
	view->state.diff.last_displayed_line = view->nlines;

	view->show = show_diff_view;
	view->input = input_diff_view;
	view->close = close_diff_view;

	return NULL;
}

static const struct got_error *
close_diff_view(struct tog_view *view)
{
	const struct got_error *err = NULL;

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

	if (asprintf(&header, "diff: %s %s",
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
input_diff_view(struct tog_view **new_view, struct tog_view **dead_view,
    struct tog_view *view, int ch)
{
	const struct got_error *err = NULL;
	struct tog_diff_view_state *s = &view->state.diff;
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
		case ']': {
			struct tog_log_view_state *ls;
			struct commit_queue_entry *entry;
			struct tog_view *diff_view;

			if (view->parent == NULL)
				break;
			if (view->parent->type != TOG_VIEW_LOG)
				break;
			ls = &view->parent->state.log;

			if (ch == '[') {
				entry = TAILQ_PREV(ls->selected_entry,
				    commit_queue_head, entry);
			} else {
				entry = TAILQ_NEXT(ls->selected_entry, entry);
				if (entry == NULL) {
					err = fetch_next_commit(&entry,
					    ls->selected_entry,
					    &ls->commits, ls->graph,
					    ls->repo, ls->in_repo_path);
					if (err)
						break;
				}
			}
			if (entry == NULL)
				break;
			err = show_commit(&diff_view, view->parent,
			    entry, ls->repo);
			if (err)
				break;
			*new_view = diff_view;
			*dead_view = view;
			break;
		}
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
	struct got_object *obj1 = NULL, *obj2 = NULL;
	char *repo_path = NULL;
	char *obj_id_str1 = NULL, *obj_id_str2 = NULL;
	int ch;
	struct tog_view *view;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc tty exec sendfd", NULL)
	    == -1)
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

	view = view_open(0, 0, 0, 0, NULL, TOG_VIEW_DIFF);
	if (view == NULL) {
		error = got_error_from_errno();
		goto done;
	}
	error = open_diff_view(view, obj1, obj2, repo);
	if (error)
		goto done;
	error = view_loop(view);
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

	if (asprintf(&line, "commit: %s", id_str) == -1) {
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
	    blame_complete ? "" : "annotating ", path) == -1) {
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

		if (nprinted == selected_line - 1)
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
		if (nprinted == selected_line - 1)
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

	err = draw_blame(a->view, a->commit_id, a->f, a->path,
	    a->lines, a->nlines, 0, *a->selected_line, a->first_displayed_line,
	    a->last_displayed_line, a->eof, a->view->nlines);
done:
	if (pthread_mutex_unlock(a->mutex) != 0)
		return got_error_from_errno();
	return err;
}

static void *
blame_thread(void *arg)
{
	const struct got_error *err;
	struct tog_blame_thread_args *ta = arg;
	struct tog_blame_cb_args *a = ta->cb_args;

	err = got_blame_incremental(ta->path, a->commit_id, ta->repo,
	    blame_cb, ta->cb_args);

	if (pthread_mutex_lock(a->mutex) != 0)
		return (void *)got_error_from_errno();

	got_repo_close(ta->repo);
	ta->repo = NULL;
	*ta->complete = 1;
	if (!err)
		err = draw_blame(a->view, a->commit_id, a->f, a->path,
		    a->lines, a->nlines, 1, *a->selected_line,
		    a->first_displayed_line, a->last_displayed_line, a->eof,
		    a->view->nlines);

	if (pthread_mutex_unlock(a->mutex) != 0 && err == NULL)
		err = got_error_from_errno();

	return (void *)err;
}

static struct got_object_id *
get_selected_commit_id(struct tog_blame_line *lines,
    int first_displayed_line, int selected_line)
{
	struct tog_blame_line *line;

	line = &lines[first_displayed_line - 1 + selected_line - 1];
	if (!line->annotated)
		return NULL;

	return line->id;
}

static const struct got_error *
open_selected_commit(struct got_object **pobj, struct got_object **obj,
    struct tog_blame_line *lines, int first_displayed_line,
    int selected_line, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_commit_object *commit = NULL;
	struct got_object_id *selected_id;
	struct got_object_qid *pid;

	*pobj = NULL;
	*obj = NULL;

	selected_id = get_selected_commit_id(lines,
	    first_displayed_line, selected_line);
	if (selected_id == NULL)
		return NULL;

	err = got_object_open(obj, repo, selected_id);
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
stop_blame(struct tog_blame *blame)
{
	const struct got_error *err = NULL;
	int i;

	if (blame->thread) {
		if (pthread_join(blame->thread, (void **)&err) != 0)
			err = got_error_from_errno();
		if (err && err->code == GOT_ERR_ITER_COMPLETED)
			err = NULL;
		blame->thread = NULL;
	}
	if (blame->thread_args.repo) {
		got_repo_close(blame->thread_args.repo);
		blame->thread_args.repo = NULL;
	}
	if (blame->f) {
		fclose(blame->f);
		blame->f = NULL;
	}
	for (i = 0; i < blame->nlines; i++)
		free(blame->lines[i].id);
	free(blame->lines);
	blame->lines = NULL;
	free(blame->cb_args.commit_id);
	blame->cb_args.commit_id = NULL;

	return err;
}

static const struct got_error *
run_blame(struct tog_blame *blame, pthread_mutex_t *mutex,
    struct tog_view *view, int *blame_complete,
    int *first_displayed_line, int *last_displayed_line,
    int *selected_line, int *done, int *eof, const char *path,
    struct got_object_id *commit_id,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_blob_object *blob = NULL;
	struct got_repository *thread_repo = NULL;
	struct got_object_id *obj_id = NULL;
	struct got_object *obj = NULL;

	err = got_object_id_by_path(&obj_id, repo, commit_id, path);
	if (err)
		goto done;

	err = got_object_open(&obj, repo, obj_id);
	if (err)
		goto done;

	if (got_object_get_type(obj) != GOT_OBJ_TYPE_BLOB) {
		err = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	err = got_object_blob_open(&blob, repo, obj, 8192);
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
	blame->cb_args.mutex = mutex;
	blame->cb_args.commit_id = got_object_id_dup(commit_id);
	if (blame->cb_args.commit_id == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	blame->cb_args.f = blame->f;
	blame->cb_args.path = path;
	blame->cb_args.first_displayed_line = first_displayed_line;
	blame->cb_args.selected_line = selected_line;
	blame->cb_args.last_displayed_line = last_displayed_line;
	blame->cb_args.quit = done;
	blame->cb_args.eof = eof;

	blame->thread_args.path = path;
	blame->thread_args.repo = thread_repo;
	blame->thread_args.cb_args = &blame->cb_args;
	blame->thread_args.complete = blame_complete;
	*blame_complete = 0;

	if (pthread_create(&blame->thread, NULL, blame_thread,
	    &blame->thread_args) != 0) {
		err = got_error_from_errno();
		goto done;
	}

done:
	if (blob)
		got_object_blob_close(blob);
	free(obj_id);
	if (obj)
		got_object_close(obj);
	if (err)
		stop_blame(blame);
	return err;
}

static const struct got_error *
open_blame_view(struct tog_view *view, char *path,
    struct got_object_id *commit_id, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct tog_blame_view_state *s = &view->state.blame;

	SIMPLEQ_INIT(&s->blamed_commits);

	if (pthread_mutex_init(&s->mutex, NULL) != 0)
		return got_error_from_errno();

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
	s->commit_id = commit_id;
	memset(&s->blame, 0, sizeof(s->blame));

	view->show = show_blame_view;
	view->input = input_blame_view;
	view->close = close_blame_view;

	return run_blame(&s->blame, &s->mutex, view, &s->blame_complete,
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

	if (pthread_mutex_lock(&s->mutex) != 0)
		return got_error_from_errno();

	err = draw_blame(view, s->blamed_commit->id, s->blame.f,
	    s->path, s->blame.lines, s->blame.nlines, s->blame_complete,
	    s->selected_line, &s->first_displayed_line,
	    &s->last_displayed_line, &s->eof, view->nlines);

	if (pthread_mutex_unlock(&s->mutex) != 0 && err == NULL)
		err = got_error_from_errno();

	return err;
}

static const struct got_error *
input_blame_view(struct tog_view **new_view, struct tog_view **dead_view,
    struct tog_view *view, int ch)
{
	const struct got_error *err = NULL, *thread_err = NULL;
	struct got_object *obj = NULL, *pobj = NULL;
	struct tog_view *diff_view;
	struct tog_blame_view_state *s = &view->state.blame;

	if (pthread_mutex_lock(&s->mutex) != 0) {
		err = got_error_from_errno();
		goto done;
	}

	switch (ch) {
		case 'q':
			s->done = 1;
			if (pthread_mutex_unlock(&s->mutex) != 0) {
				err = got_error_from_errno();
				goto done;
			}
			return stop_blame(&s->blame);
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
			struct got_object_id *id;
			id = get_selected_commit_id(s->blame.lines,
			    s->first_displayed_line, s->selected_line);
			if (id == NULL || got_object_id_cmp(id,
			    s->blamed_commit->id) == 0)
				break;
			err = open_selected_commit(&pobj, &obj,
			    s->blame.lines, s->first_displayed_line,
			    s->selected_line, s->repo);
			if (err)
				break;
			if (pobj == NULL && obj == NULL)
				break;
			if (ch == 'p' && pobj == NULL)
				break;
			s->done = 1;
			if (pthread_mutex_unlock(&s->mutex) != 0) {
				err = got_error_from_errno();
				goto done;
			}
			thread_err = stop_blame(&s->blame);
			s->done = 0;
			if (pthread_mutex_lock(&s->mutex) != 0) {
				err = got_error_from_errno();
				goto done;
			}
			if (thread_err)
				break;
			id = got_object_get_id(ch == 'b' ? obj : pobj);
			got_object_close(obj);
			obj = NULL;
			if (pobj) {
				got_object_close(pobj);
				pobj = NULL;
			}
			err = got_object_qid_alloc(&s->blamed_commit, id);
			if (err)
				goto done;
			SIMPLEQ_INSERT_HEAD(&s->blamed_commits,
			    s->blamed_commit, entry);
			err = run_blame(&s->blame, &s->mutex, view,
			    &s->blame_complete,
			    &s->first_displayed_line,
			    &s->last_displayed_line,
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
			if (pthread_mutex_unlock(&s->mutex) != 0) {
				err = got_error_from_errno();
				goto done;
			}
			thread_err = stop_blame(&s->blame);
			s->done = 0;
			if (pthread_mutex_lock(&s->mutex) != 0) {
				err = got_error_from_errno();
				goto done;
			}
			if (thread_err)
				break;
			SIMPLEQ_REMOVE_HEAD(&s->blamed_commits, entry);
			got_object_qid_free(s->blamed_commit);
			s->blamed_commit =
			    SIMPLEQ_FIRST(&s->blamed_commits);
			err = run_blame(&s->blame, &s->mutex, view,
			    &s->blame_complete,
			    &s->first_displayed_line,
			    &s->last_displayed_line,
			    &s->selected_line, &s->done, &s->eof, s->path,
			    s->blamed_commit->id, s->repo);
			if (err)
				break;
			break;
		}
		case KEY_ENTER:
		case '\r':
			err = open_selected_commit(&pobj, &obj,
			    s->blame.lines, s->first_displayed_line,
			    s->selected_line, s->repo);
			if (err)
				break;
			if (pobj == NULL && obj == NULL)
				break;
			diff_view = view_open(0, 0, 0, 0, view,
			    TOG_VIEW_DIFF);
			if (diff_view == NULL) {
				err = got_error_from_errno();
				break;
			}
			err = open_diff_view(diff_view, pobj, obj,
			    s->repo);
			if (err) {
				view_close(diff_view);
				break;
			}
			*new_view = diff_view;
			if (pobj) {
				got_object_close(pobj);
				pobj = NULL;
			}
			got_object_close(obj);
			obj = NULL;
			if (err)
				break;
			break;
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

	if (pthread_mutex_unlock(&s->mutex) != 0)
		err = got_error_from_errno();
done:
	if (pobj)
		got_object_close(pobj);
	return thread_err ? thread_err : err;
}

static const struct got_error *
cmd_blame(int argc, char *argv[])
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	char *path, *cwd = NULL, *repo_path = NULL, *in_repo_path = NULL;
	struct got_object_id *commit_id = NULL;
	char *commit_id_str = NULL;
	int ch;
	struct tog_view *view;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc tty exec sendfd", NULL)
	    == -1)
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
		repo_path = strdup(cwd);
		if (repo_path == NULL) {
			error = got_error_from_errno();
			goto done;
		}
	}


	error = got_repo_open(&repo, repo_path);
	if (error != NULL)
		return error;

	error = got_repo_map_path(&in_repo_path, repo, path);
	if (error != NULL)
		goto done;

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
		commit_id = got_object_id_dup(got_object_get_id(obj));
		if (commit_id == NULL)
			error = got_error_from_errno();
		got_object_close(obj);
	}
	if (error != NULL)
		goto done;

	view = view_open(0, 0, 0, 0, NULL, TOG_VIEW_BLAME);
	if (view == NULL) {
		error = got_error_from_errno();
		goto done;
	}
	error = open_blame_view(view, in_repo_path, commit_id, repo);
	if (error)
		goto done;
	error = view_loop(view);
done:
	free(repo_path);
	free(cwd);
	free(commit_id);
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
			wstandout(view->window);
			*selected_entry = NULL;
		}
		waddstr(view->window, "  ..\n");	/* parent directory */
		if (selected == 0)
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
		    te->name, S_ISDIR(te->mode) ? "/" : "") == -1) {
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
			wstandout(view->window);
			*selected_entry = te;
		}
		waddwstr(view->window, wline);
		if (width < view->ncols)
			waddch(view->window, '\n');
		if (n == selected)
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

	view_vborder(view);
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
blame_tree_entry(struct tog_view **new_view, struct tog_view *parent_view,
    struct got_tree_entry *te, struct tog_parent_trees *parents,
    struct got_object_id *commit_id, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *path;
	struct tog_view *blame_view;

	err = tree_entry_path(&path, parents, te);
	if (err)
		return err;

	blame_view = view_open(0, 0, 0, 0, parent_view, TOG_VIEW_BLAME);
	if (blame_view == NULL)
		return got_error_from_errno();

	err = open_blame_view(blame_view, path, commit_id, repo);
	if (err) {
		view_close(blame_view);
		free(path);
	} else
		*new_view = blame_view;
	return err;
}

static const struct got_error *
log_tree_entry(struct tog_view **new_view, struct tog_view *parent_view,
    struct got_tree_entry *te, struct tog_parent_trees *parents,
    struct got_object_id *commit_id, struct got_repository *repo)
{
	struct tog_view *log_view;
	const struct got_error *err = NULL;
	char *path;

	log_view = view_open(0, 0, 0, 0, parent_view, TOG_VIEW_LOG);
	if (log_view == NULL)
		return got_error_from_errno();

	err = tree_entry_path(&path, parents, te);
	if (err)
		return err;

	err = open_log_view(log_view, commit_id, repo, path);
	if (err)
		view_close(log_view);
	else
		*new_view = log_view;
	free(path);
	return err;
}

static const struct got_error *
open_tree_view(struct tog_view *view, struct got_tree_object *root,
    struct got_object_id *commit_id, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *commit_id_str = NULL;
	struct tog_tree_view_state *s = &view->state.tree;

	TAILQ_INIT(&s->parents);

	err = got_object_id_str(&commit_id_str, commit_id);
	if (err != NULL)
		goto done;

	if (asprintf(&s->tree_label, "commit: %s", commit_id_str) == -1) {
		err = got_error_from_errno();
		goto done;
	}

	s->root = s->tree = root;
	s->entries = got_object_tree_get_entries(root);
	s->first_displayed_entry = SIMPLEQ_FIRST(&s->entries->head);
	s->commit_id = commit_id;
	s->repo = repo;

	view->show = show_tree_view;
	view->input = input_tree_view;
	view->close = close_tree_view;
done:
	free(commit_id_str);
	if (err)
		free(s->tree_label);
	return err;
}

static const struct got_error *
close_tree_view(struct tog_view *view)
{
	struct tog_tree_view_state *s = &view->state.tree;

	free(s->tree_label);
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
	return err;
}

static const struct got_error *
input_tree_view(struct tog_view **new_view, struct tog_view **dead_view,
    struct tog_view *view, int ch)
{
	const struct got_error *err = NULL;
	struct tog_tree_view_state *s = &view->state.tree;

	switch (ch) {
		case 'i':
			s->show_ids = !s->show_ids;
			break;
		case 'l':
			if (s->selected_entry) {
				err = log_tree_entry(new_view, view,
				    s->selected_entry, &s->parents,
				    s->commit_id, s->repo);
			}
			break;
		case 'k':
		case KEY_UP:
			if (s->selected > 0)
				s->selected--;
			if (s->selected > 0)
				break;
			tree_scroll_up(&s->first_displayed_entry, 1,
			    s->entries, s->tree == s->root);
			break;
		case KEY_PPAGE:
			if (SIMPLEQ_FIRST(&s->entries->head) ==
			    s->first_displayed_entry) {
				if (s->tree != s->root)
					s->first_displayed_entry = NULL;
				s->selected = 0;
				break;
			}
			tree_scroll_up(&s->first_displayed_entry,
			    view->nlines, s->entries,
			    s->tree == s->root);
			break;
		case 'j':
		case KEY_DOWN:
			if (s->selected < s->ndisplayed - 1) {
				s->selected++;
				break;
			}
			tree_scroll_down(&s->first_displayed_entry, 1,
			    s->last_displayed_entry, s->entries);
			break;
		case KEY_NPAGE:
			tree_scroll_down(&s->first_displayed_entry,
			    view->nlines, s->last_displayed_entry,
			    s->entries);
			if (SIMPLEQ_NEXT(s->last_displayed_entry,
			    entry))
				break;
			/* can't scroll any further; move cursor down */
			if (s->selected < s->ndisplayed - 1)
				s->selected = s->ndisplayed - 1;
			break;
		case KEY_ENTER:
		case '\r':
			if (s->selected_entry == NULL) {
				struct tog_parent_tree *parent;
		case KEY_LEFT:
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
				err = blame_tree_entry(new_view, view,
				    s->selected_entry, &s->parents,
				    s->commit_id, s->repo);
				if (err)
					break;
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
	char *repo_path = NULL;
	struct got_object_id *commit_id = NULL;
	char *commit_id_arg = NULL;
	struct got_commit_object *commit = NULL;
	struct got_tree_object *tree = NULL;
	int ch;
	struct tog_view *view;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath flock proc tty exec sendfd", NULL)
	    == -1)
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
			commit_id = got_object_id_dup(got_object_get_id(obj));
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

	view = view_open(0, 0, 0, 0, NULL, TOG_VIEW_TREE);
	if (view == NULL) {
		error = got_error_from_errno();
		goto done;
	}
	error = open_tree_view(view, tree, commit_id, repo);
	if (error)
		goto done;
	error = view_loop(view);
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
