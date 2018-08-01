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

struct tog_view {
	WINDOW *window;
	PANEL *panel;
	int nlines, ncols, begin_y, begin_x;
	int lines, cols; /* copies of LINES and COLS */
};

static const struct got_error *
show_diff_view(struct tog_view *, struct got_object *, struct got_object *,
    struct got_repository *);
static const struct got_error *
show_log_view(struct tog_view *, struct got_object_id *,
    struct got_repository *, const char *);
static const struct got_error *
show_blame_view(struct tog_view *, const char *, struct got_object_id *,
    struct got_repository *);
static const struct got_error *
show_tree_view(struct got_tree_object *, struct got_object_id *,
    struct got_repository *);

static void
close_view(struct tog_view *view)
{
	if (view->panel)
		del_panel(view->panel);
	if (view->window)
		delwin(view->window);
	free(view);
}

static struct tog_view *
open_view(int nlines, int ncols, int begin_y, int begin_x)
{
	struct tog_view *view = malloc(sizeof(*view));

	if (view == NULL)
		return NULL;

	view->lines = LINES;
	view->cols = COLS;
	view->nlines = nlines ? nlines : LINES - begin_y;
	view->ncols = ncols ? ncols : COLS - begin_x;
	view->begin_y = begin_y;
	view->begin_x = begin_x;
	view->window = newwin(nlines, ncols, begin_y, begin_x);
	if (view->window == NULL) {
		close_view(view);
		return NULL;
	}
	view->panel = new_panel(view->window);
	if (view->panel == NULL) {
		close_view(view);
		return NULL;
	}

	keypad(view->window, TRUE);
	return view;
}

const struct got_error *
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

	view->nlines = nlines;
	view->ncols = ncols;
	view->lines = LINES;
	view->cols = COLS;
	return NULL;
}

__dead static void
usage_log(void)
{
	endwin();
	fprintf(stderr, "usage: %s log [-c commit] [-r repository-path] [path]\n",
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

	if (strftime(datebuf, sizeof(datebuf), "%g/%m/%d ", &commit->tm_committer)
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
	int nfetched, nqueued = 0, found_obj = 0;
	int is_root_path = strcmp(path, "/") == 0;

	err = got_commit_graph_iter_start(graph, start_id);
	if (err)
		return err;

	entry = TAILQ_LAST(&commits->head, commit_queue_head);
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
			if (err->code != GOT_ERR_ITER_NEED_MORE)
				break;
			if (nqueued >= minqueue) {
				err = NULL;
				break;
			}
			err = got_commit_graph_fetch_commits(&nfetched,
			    graph, 1, repo);
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
			struct got_object *obj;
			struct got_object_qid *pid;
			int changed = 0;

			err = got_object_open_by_path(&obj, repo, id, path);
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
						got_object_close(obj);
						got_object_close(pobj);
						break;
					}
					pid = got_object_get_id(pobj);
					if (pid == NULL) {
						err = got_error_from_errno();
						free(id);
						got_object_close(obj);
						got_object_close(pobj);
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

	if (path) {
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

	waddwstr(view->window, wline);
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
show_commit(struct commit_queue_entry *entry, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_object *obj1 = NULL, *obj2 = NULL;
	struct got_object_qid *parent_id;
	struct tog_view *view;

	err = got_object_open(&obj2, repo, entry->id);
	if (err)
		return err;

	parent_id = SIMPLEQ_FIRST(&entry->commit->parent_ids);
	if (parent_id) {
		err = got_object_open(&obj1, repo, parent_id->id);
		if (err)
			goto done;
	}

	view = open_view(0, 0, 0, 0);
	if (view == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	err = show_diff_view(view, obj1, obj2, repo);
	close_view(view);
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
show_log_view(struct tog_view *view, struct got_object_id *start_id,
    struct got_repository *repo, const char *path)
{
	const struct got_error *err = NULL;
	struct got_object_id *head_id = NULL;
	int ch, done = 0, selected = 0, nfetched;
	struct got_commit_graph *graph = NULL;
	struct commit_queue commits;
	struct commit_queue_entry *first_displayed_entry = NULL;
	struct commit_queue_entry *last_displayed_entry = NULL;
	struct commit_queue_entry *selected_entry = NULL;
	char *in_repo_path = NULL;

	err = got_repo_map_path(&in_repo_path, repo, path);
	if (err != NULL)
		goto done;

	err = get_head_commit_id(&head_id, repo);
	if (err)
		return err;

	/* The graph contains all commits. */
	err = got_commit_graph_open(&graph, head_id, 0, repo);
	if (err)
		goto done;
	/* The commit queue contains a subset of commits filtered by path. */
	TAILQ_INIT(&commits.head);
	commits.ncommits = 0;

	/* Populate commit graph with a sufficient number of commits. */
	err = got_commit_graph_fetch_commits_up_to(&nfetched, graph, start_id,
	    repo);
	if (err)
		goto done;

	/*
	 * Open the initial batch of commits, sorted in commit graph order.
	 * We keep all commits open throughout the lifetime of the log view
	 * in order to avoid having to re-fetch commits from disk while
	 * updating the display.
	 */
	err = queue_commits(graph, &commits, start_id, view->nlines, 1, repo,
	    in_repo_path);
	if (err) {
		if (err->code != GOT_ERR_ITER_COMPLETED)
			goto done;
		err = NULL;
	}

	show_panel(view->panel);

	first_displayed_entry = TAILQ_FIRST(&commits.head);
	selected_entry = first_displayed_entry;
	while (!done) {
		err = draw_commits(view, &last_displayed_entry, &selected_entry,
		    first_displayed_entry, &commits, selected, view->nlines,
		    graph, repo, in_repo_path);
		if (err)
			goto done;

		nodelay(stdscr, FALSE);
		ch = wgetch(view->window);
		nodelay(stdscr, TRUE);
		switch (ch) {
			case ERR:
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
				if (TAILQ_FIRST(&commits.head) ==
				    first_displayed_entry) {
					selected = 0;
					break;
				}
				scroll_up(&first_displayed_entry, view->nlines,
				    &commits);
				break;
			case 'j':
			case KEY_DOWN:
				if (selected < MIN(view->nlines - 2,
				    commits.ncommits - 1)) {
					selected++;
					break;
				}
				err = scroll_down(&first_displayed_entry, 1,
				    last_displayed_entry, &commits, graph,
				    repo, in_repo_path);
				if (err) {
					if (err->code != GOT_ERR_ITER_COMPLETED)
						goto done;
					err = NULL;
				}
				break;
			case KEY_NPAGE: {
				struct commit_queue_entry *first = first_displayed_entry;
				err = scroll_down(&first_displayed_entry, view->nlines,
				    last_displayed_entry, &commits, graph,
				    repo, in_repo_path);
				if (err) {
					if (err->code != GOT_ERR_ITER_COMPLETED)
						goto done;
					/* can't scroll any further; move cursor down */
					if (first == first_displayed_entry && selected <
					    MIN(view->nlines - 2, commits.ncommits - 1)) {
						selected = MIN(view->nlines - 2,
						    commits.ncommits - 1);
					}
					err = NULL;
				}
				break;
			}
			case KEY_RESIZE:
				err = view_resize(view);
				if (err)
					goto done;
				if (selected > view->nlines - 2)
					selected = view->nlines - 2;
				if (selected > commits.ncommits - 1)
					selected = commits.ncommits - 1;
				break;
			case KEY_ENTER:
			case '\r':
				err = show_commit(selected_entry, repo);
				if (err)
					goto done;
				show_panel(view->panel);
				break;
			case 't':
				err = browse_commit(selected_entry, repo);
				if (err)
					goto done;
				show_panel(view->panel);
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
	free(in_repo_path);
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
	if (pledge("stdio rpath wpath cpath flock proc tty", NULL) == -1)
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
			start_id = got_object_get_id(obj);
			if (start_id == NULL)
				error = got_error_from_errno();
				goto done;
		}
	}
	if (error != NULL)
		goto done;

	view = open_view(0, 0, 0, 0);
	if (view == NULL) {
		error = got_error_from_errno();
		goto done;
	}
	error = show_log_view(view, start_id, repo, path);
	close_view(view);
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
    int *last_displayed_line, int *eof, int max_lines)
{
	const struct got_error *err;
	int nlines = 0, nprinted = 0;
	char *line;
	size_t len;
	wchar_t *wline;
	int width;

	rewind(f);
	werase(view->window);

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
			free(wline);
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

	update_panels();
	doupdate();

	return NULL;
}

static const struct got_error *
show_diff_view(struct tog_view *view, struct got_object *obj1,
    struct got_object *obj2, struct got_repository *repo)
{
	const struct got_error *err;
	FILE *f;
	int ch, done = 0;
	int first_displayed_line = 1, last_displayed_line = view->nlines;
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

	show_panel(view->panel);

	while (!done) {
		err = draw_file(view, f, &first_displayed_line,
		    &last_displayed_line, &eof, view->nlines);
		if (err)
			break;
		nodelay(stdscr, FALSE);
		ch = wgetch(view->window);
		nodelay(stdscr, TRUE);
		switch (ch) {
			case 'q':
				done = 1;
				break;
			case 'k':
			case KEY_UP:
				if (first_displayed_line > 1)
					first_displayed_line--;
				break;
			case KEY_PPAGE:
			case KEY_BACKSPACE:
				i = 0;
				while (i++ < view->nlines - 1 &&
				    first_displayed_line > 1)
					first_displayed_line--;
				break;
			case 'j':
			case KEY_DOWN:
				if (!eof)
					first_displayed_line++;
				break;
			case KEY_NPAGE:
			case ' ':
				i = 0;
				while (!eof && i++ < view->nlines - 1) {
					char *line = parse_next_line(f, NULL);
					first_displayed_line++;
					if (line == NULL)
						break;
				}
				break;
			case KEY_RESIZE:
				err = view_resize(view);
				if (err)
					goto done;
				break;
			default:
				break;
		}
	}
done:
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
	struct tog_view *view;

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

	view = open_view(0, 0, 0, 0);
	if (view == NULL) {
		error = got_error_from_errno();
		goto done;
	}
	error = show_diff_view(view, obj1, obj2, repo);
	close_view(view);
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
	waddwstr(view->window, wline);
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

	update_panels();
	doupdate();

	return NULL;
}

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

	err = draw_blame(a->view, a->commit_id, a->f, a->path,
	    a->lines, a->nlines, 0, *a->selected_line, a->first_displayed_line,
	    a->last_displayed_line, &eof, a->view->nlines);
done:
	if (pthread_mutex_unlock(a->mutex) != 0)
		return got_error_from_errno();
	return err;
}

struct tog_blame_thread_args {
	const char *path;
	struct got_repository *repo;
	struct tog_blame_cb_args *cb_args;
	int *complete;
};

static void *
blame_thread(void *arg)
{
	const struct got_error *err;
	struct tog_blame_thread_args *ta = arg;
	struct tog_blame_cb_args *a = ta->cb_args;
	int eof;

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
		    a->first_displayed_line, a->last_displayed_line, &eof,
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
    int *selected_line, int *done, const char *path,
    struct got_object_id *commit_id,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_blob_object *blob = NULL;
	struct got_repository *thread_repo = NULL;
	struct got_object *obj;

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
	if (obj)
		got_object_close(obj);
	if (err)
		stop_blame(blame);
	return err;
}

static const struct got_error *
show_blame_view(struct tog_view *view, const char *path,
    struct got_object_id *commit_id, struct got_repository *repo)
{
	const struct got_error *err = NULL, *thread_err = NULL;
	int ch, done = 0, first_displayed_line = 1, last_displayed_line;
	int selected_line = first_displayed_line;
	int eof, blame_complete = 0;
	struct got_object *obj = NULL, *pobj = NULL;
	pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	struct tog_blame blame;
	struct got_object_id_queue blamed_commits;
	struct got_object_qid *blamed_commit = NULL;
	struct tog_view *diff_view;

	SIMPLEQ_INIT(&blamed_commits);

	if (pthread_mutex_init(&mutex, NULL) != 0) {
		err = got_error_from_errno();
		goto done;
	}

	err = got_object_qid_alloc(&blamed_commit, commit_id);
	if (err)
		goto done;
	SIMPLEQ_INSERT_HEAD(&blamed_commits, blamed_commit, entry);

	show_panel(view->panel);
	last_displayed_line = view->nlines;

	memset(&blame, 0, sizeof(blame));
	err = run_blame(&blame, &mutex, view, &blame_complete,
	    &first_displayed_line, &last_displayed_line,
	    &selected_line, &done, path, blamed_commit->id, repo);
	if (err)
		return err;

	while (!done) {
		if (pthread_mutex_lock(&mutex) != 0) {
			err = got_error_from_errno();
			goto done;
		}
		err = draw_blame(view, blamed_commit->id, blame.f, path,
		    blame.lines, blame.nlines, blame_complete, selected_line,
		    &first_displayed_line, &last_displayed_line, &eof,
		    view->nlines);
		if (pthread_mutex_unlock(&mutex) != 0) {
			err = got_error_from_errno();
			goto done;
		}
		if (err)
			break;
		nodelay(stdscr, FALSE);
		ch = wgetch(view->window);
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
			case KEY_BACKSPACE:
				if (first_displayed_line == 1) {
					selected_line = 1;
					break;
				}
				if (first_displayed_line > view->nlines - 2)
					first_displayed_line -=
					    (view->nlines - 2);
				else
					first_displayed_line = 1;
				break;
			case 'j':
			case KEY_DOWN:
				if (selected_line < view->nlines - 2 &&
				    first_displayed_line + selected_line <=
				    blame.nlines)
					selected_line++;
				else if (last_displayed_line < blame.nlines)
					first_displayed_line++;
				break;
			case 'b':
			case 'p': {
				struct got_object_id *id;
				id = get_selected_commit_id(blame.lines,
				    first_displayed_line, selected_line);
				if (id == NULL || got_object_id_cmp(id,
				    blamed_commit->id) == 0)
					break;
				err = open_selected_commit(&pobj, &obj,
				    blame.lines, first_displayed_line,
				    selected_line, repo);
				if (err)
					break;
				if (pobj == NULL && obj == NULL)
					break;
				if (ch == 'p' && pobj == NULL)
					break;
				done = 1;
				if (pthread_mutex_unlock(&mutex) != 0) {
					err = got_error_from_errno();
					goto done;
				}
				thread_err = stop_blame(&blame);
				done = 0;
				if (pthread_mutex_lock(&mutex) != 0) {
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
				if (id == NULL) {
					err = got_error_from_errno();
					break;
				}
				err = got_object_qid_alloc(&blamed_commit, id);
				free(id);
				if (err)
					goto done;
				SIMPLEQ_INSERT_HEAD(&blamed_commits,
				    blamed_commit, entry);
				err = run_blame(&blame, &mutex, view,
				    &blame_complete, &first_displayed_line,
				    &last_displayed_line, &selected_line,
				    &done, path, blamed_commit->id, repo);
				if (err)
					break;
				break;
			}
			case 'B': {
				struct got_object_qid *first;
				first = SIMPLEQ_FIRST(&blamed_commits);
				if (!got_object_id_cmp(first->id, commit_id))
					break;
				done = 1;
				if (pthread_mutex_unlock(&mutex) != 0) {
					err = got_error_from_errno();
					goto done;
				}
				thread_err = stop_blame(&blame);
				done = 0;
				if (pthread_mutex_lock(&mutex) != 0) {
					err = got_error_from_errno();
					goto done;
				}
				if (thread_err)
					break;
				SIMPLEQ_REMOVE_HEAD(&blamed_commits, entry);
				got_object_qid_free(blamed_commit);
				blamed_commit = SIMPLEQ_FIRST(&blamed_commits);
				err = run_blame(&blame, &mutex, view,
				    &blame_complete, &first_displayed_line,
				    &last_displayed_line, &selected_line,
				    &done, path, blamed_commit->id, repo);
				if (err)
					break;
				break;
			}
			case KEY_ENTER:
			case '\r':
				err = open_selected_commit(&pobj, &obj,
				    blame.lines, first_displayed_line,
				    selected_line, repo);
				if (err)
					break;
				if (pobj == NULL && obj == NULL)
					break;
				diff_view = open_view(0, 0, 0, 0);
				if (diff_view == NULL) {
					err = got_error_from_errno();
					break;
				}
				err = show_diff_view(diff_view, pobj, obj, repo);
				close_view(diff_view);
				if (pobj) {
					got_object_close(pobj);
					pobj = NULL;
				}
				got_object_close(obj);
				obj = NULL;
				show_panel(view->panel);
				if (err)
					break;
				break;
			case KEY_NPAGE:
			case ' ':
				if (last_displayed_line >= blame.nlines &&
				    selected_line < view->nlines - 2) {
					selected_line = MIN(blame.nlines,
					    view->nlines - 2);
					break;
				}
				if (last_displayed_line + view->nlines - 2 <=
				    blame.nlines)
					first_displayed_line +=
					    view->nlines - 2;
				else
					first_displayed_line =
					    blame.nlines - (view->nlines - 3);
				break;
			case KEY_RESIZE:
				err = view_resize(view);
				if (err)
					break;
				if (selected_line > view->nlines - 2) {
					selected_line = MIN(blame.nlines,
					    view->nlines - 2);
				}
				break;
			default:
				break;
		}
		if (pthread_mutex_unlock(&mutex) != 0)
			err = got_error_from_errno();
		if (err || thread_err)
			break;
	}
done:
	if (pobj)
		got_object_close(pobj);
	if (blame.thread)
		thread_err = stop_blame(&blame);
	while (!SIMPLEQ_EMPTY(&blamed_commits)) {
		blamed_commit = SIMPLEQ_FIRST(&blamed_commits);
		SIMPLEQ_REMOVE_HEAD(&blamed_commits, entry);
		got_object_qid_free(blamed_commit);
	}
	return thread_err ? thread_err : err;
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
	struct tog_view *view;

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

	view = open_view(0, 0, 0, 0);
	if (view == NULL) {
		error = got_error_from_errno();
		goto done;
	}
	error = show_blame_view(view, path, commit_id, repo);
	close_view(view);
done:
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
	waddwstr(view->window, wline);
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
blame_tree_entry(struct tog_view *view, struct got_tree_entry *te,
    struct tog_parent_trees *parents, struct got_object_id *commit_id,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *path;

	err = tree_entry_path(&path, parents, te);
	if (err)
		return err;

	err = show_blame_view(view, path, commit_id, repo);
	free(path);
	return err;
}

static const struct got_error *
log_tree_entry(struct tog_view *view, struct got_tree_entry *te,
    struct tog_parent_trees *parents, struct got_object_id *commit_id,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	char *path;

	err = tree_entry_path(&path, parents, te);
	if (err)
		return err;

	err = show_log_view(view, commit_id, repo, path);
	free(path);
	return err;
}

static const struct got_error *
show_tree_view(struct got_tree_object *root, struct got_object_id *commit_id,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	int ch, done = 0, selected = 0, show_ids = 0;
	struct got_tree_object *tree = root;
	const struct got_tree_entries *entries;
	struct got_tree_entry *first_displayed_entry = NULL;
	struct got_tree_entry *last_displayed_entry = NULL;
	struct got_tree_entry *selected_entry = NULL;
	char *commit_id_str = NULL, *tree_label = NULL;
	int nentries, ndisplayed;
	struct tog_parent_trees parents;
	struct tog_view *view = NULL;

	TAILQ_INIT(&parents);

	err = got_object_id_str(&commit_id_str, commit_id);
	if (err != NULL)
		goto done;

	if (asprintf(&tree_label, "commit: %s", commit_id_str) == -1) {
		err = got_error_from_errno();
		goto done;
	}

	view = open_view(0, 0, 0, 0);
	if (view == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	show_panel(view->panel);

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

		err = draw_tree_entries(view, &first_displayed_entry,
		    &last_displayed_entry, &selected_entry, &ndisplayed,
		    tree_label, show_ids, parent_path, entries, selected,
		    view->nlines, tree == root);
		free(parent_path);
		if (err)
			break;

		nodelay(stdscr, FALSE);
		ch = wgetch(view->window);
		nodelay(stdscr, TRUE);
		switch (ch) {
			case 'q':
				done = 1;
				break;
			case 'i':
				show_ids = !show_ids;
				break;
			case 'l':
				if (selected_entry) {
					struct tog_view *log_view;
					log_view = open_view(0, 0, 0, 0);
					if (log_view == NULL) {
						err = got_error_from_errno();
						goto done;
					}
					err = log_tree_entry(log_view,
					    selected_entry, &parents,
					    commit_id, repo);
					close_view(log_view);
					if (err)
						goto done;
				}
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
				tree_scroll_up(&first_displayed_entry,
				    view->nlines, entries, tree == root);
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
				tree_scroll_down(&first_displayed_entry,
				    view->nlines, last_displayed_entry,
				    entries);
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
					struct tog_view *blame_view;
					blame_view = open_view(0, 0, 0, 0);
					if (blame_view == NULL) {
						err = got_error_from_errno();
						goto done;
					}
					err = blame_tree_entry(blame_view,
					    selected_entry, &parents,
					    commit_id, repo);
					close_view(blame_view);
					if (err)
						goto done;
				}
				break;
			case KEY_RESIZE:
				err = view_resize(view);
				if (err)
					goto done;
				if (selected > view->nlines)
					selected = ndisplayed - 1;
				break;
			default:
				break;
		}
	}
done:
	if (view)
		close_view(view);
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
