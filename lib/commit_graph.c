/*
 * Copyright (c) 2018, 2019, 2020 Stefan Sperling <stsp@openbsd.org>
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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <ctype.h>

#include "got_compat.h"

#include "got_error.h"
#include "got_object.h"
#include "got_cancel.h"
#include "got_commit_graph.h"
#include "got_path.h"

#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_object_idset.h"
#include "got_lib_object_qid.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

struct got_commit_graph_node {
	struct got_object_id id;

	/* Used for topological sorting. */
	struct got_commit_graph_node *parents[2];
	struct got_commit_graph_node **more_parents;
	int nparents;
	int indegree;

	/* Used only during iteration. */
	time_t timestamp;
	TAILQ_ENTRY(got_commit_graph_node) entry;
};

TAILQ_HEAD(got_commit_graph_iter_list, got_commit_graph_node);

struct got_commit_graph_branch_tip {
	struct got_object_id *commit_id;
	struct got_commit_object *commit;
	struct got_commit_graph_node *new_node;
};

struct got_commit_graph {
	/* The set of all commits we have traversed. */
	struct got_object_idset *node_ids;

	int flags;
#define GOT_COMMIT_GRAPH_FIRST_PARENT_TRAVERSAL		0x01
#define GOT_COMMIT_GRAPH_TOPOSORT			0x02

	/*
	 * A set of object IDs of known parent commits which we have not yet
	 * traversed. Each commit ID in this set represents a branch in commit
	 * history: Either the first-parent branch of the head node, or another
	 * branch corresponding to a traversed merge commit for which we have
	 * not traversed a branch point commit yet.
	 *
	 * Whenever we add a commit with a matching ID to the graph, we remove
	 * its corresponding element from this set, and add new elements for
	 * each of that commit's parent commits which were not traversed yet.
	 *
	 * When API users ask us to fetch more commits, we fetch commits from
	 * all currently open branches. This allows API users to process
	 * commits in linear order even though the history contains branches.
	 */
	struct got_object_idset *open_branches;

	/* Array of branch tips for fetch_commits_from_open_branches(). */
	struct got_commit_graph_branch_tip *tips;
	int ntips;

	/* Path of tree entry of interest to the API user. */
	char *path;

	/*
	 * Nodes which will be passed to the API user next, sorted by
	 * commit timestamp. Sorted in topological order only if topological
	 * sorting was requested.
	 */
	struct got_commit_graph_iter_list iter_list;
};

static const struct got_error *
detect_changed_path(int *changed, struct got_commit_object *commit,
    struct got_object_id *commit_id, const char *path,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_commit_object *pcommit = NULL;
	struct got_tree_object *tree = NULL, *ptree = NULL;
	struct got_object_qid *pid;

	if (got_path_is_root_dir(path)) {
		*changed = 1;
		return NULL;
	}

	*changed = 0;

	pid = STAILQ_FIRST(&commit->parent_ids);
	if (pid == NULL) {
		struct got_object_id *obj_id;
		err = got_object_id_by_path(&obj_id, repo, commit, path);
		if (err) {
			if (err->code == GOT_ERR_NO_TREE_ENTRY)
				err = NULL;
		} else
			*changed = 1; /* The path was created in this commit. */
		free(obj_id);
		return err;
	}

	err = got_object_open_as_tree(&tree, repo, commit->tree_id);
	if (err)
		return err;

	err = got_object_open_as_commit(&pcommit, repo, &pid->id);
	if (err)
		goto done;

	err = got_object_open_as_tree(&ptree, repo, pcommit->tree_id);
	if (err)
		goto done;

	err = got_object_tree_path_changed(changed, tree, ptree, path, repo);
done:
	if (tree)
		got_object_tree_close(tree);
	if (ptree)
		got_object_tree_close(ptree);
	if (pcommit)
		got_object_commit_close(pcommit);
	return err;
}

static void
add_node_to_iter_list(struct got_commit_graph *graph,
    struct got_commit_graph_node *node, time_t committer_time)
{
	struct got_commit_graph_node *n, *next;

	node->timestamp = committer_time;

	n = TAILQ_FIRST(&graph->iter_list);
	while (n) {
		next = TAILQ_NEXT(n, entry);
		if (next && node->timestamp >= next->timestamp) {
			TAILQ_INSERT_BEFORE(next, node, entry);
			return;
		}
		n = next;
	}
	TAILQ_INSERT_TAIL(&graph->iter_list, node, entry);
}

static const struct got_error *
add_node(struct got_commit_graph_node **new_node,
    struct got_commit_graph *graph, struct got_object_id *commit_id,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_commit_graph_node *node;

	*new_node = NULL;

	node = calloc(1, sizeof(*node));
	if (node == NULL)
		return got_error_from_errno("calloc");

	memcpy(&node->id, commit_id, sizeof(node->id));
	node->nparents = -1;
	err = got_object_idset_add(graph->node_ids, &node->id, node);
	if (err)
		free(node);
	else
		*new_node = node;
	return err;
}

/*
 * Ask got-read-pack to traverse first-parent history until a commit is
 * encountered which modified graph->path, or until the pack file runs
 * out of relevant commits. This is faster than sending an individual
 * request for each commit stored in the pack file.
 */
static const struct got_error *
packed_first_parent_traversal(int *ncommits_traversed,
    struct got_commit_graph *graph, struct got_object_id *commit_id,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_object_id_queue traversed_commits;
	struct got_object_qid *qid;

	STAILQ_INIT(&traversed_commits);
	*ncommits_traversed = 0;

	err = got_traverse_packed_commits(&traversed_commits,
	    commit_id, graph->path, repo);
	if (err)
		return err;

	/* Add all traversed commits to the graph... */
	STAILQ_FOREACH(qid, &traversed_commits, entry) {
		if (got_object_idset_contains(graph->open_branches, &qid->id))
			continue;
		if (got_object_idset_contains(graph->node_ids, &qid->id))
			continue;

		(*ncommits_traversed)++;

		/* ... except the last commit is the new branch tip. */
		if (STAILQ_NEXT(qid, entry) == NULL) {
			err = got_object_idset_add(graph->open_branches,
			    &qid->id, NULL);
			break;
		}

		err = got_object_idset_add(graph->node_ids, &qid->id, NULL);
		if (err)
			break;
	}

	got_object_id_queue_free(&traversed_commits);
	return err;
}

static const struct got_error *
close_branch(struct got_commit_graph *graph, struct got_object_id *commit_id)
{
	const struct got_error *err;

	err = got_object_idset_remove(NULL, graph->open_branches, commit_id);
	if (err && err->code != GOT_ERR_NO_OBJ)
		return err;
	return NULL;
}

static const struct got_error *
advance_branch(struct got_commit_graph *graph, struct got_object_id *commit_id,
    struct got_commit_object *commit, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_object_qid *qid;
	struct got_object_id *merged_id = NULL;

	err = close_branch(graph, commit_id);
	if (err)
		return err;

	if (graph->flags & GOT_COMMIT_GRAPH_FIRST_PARENT_TRAVERSAL) {
		qid = STAILQ_FIRST(&commit->parent_ids);
		if (qid == NULL ||
		    got_object_idset_contains(graph->open_branches, &qid->id))
			return NULL;
		/*
		 * The root directory always changes by definition, and when
		 * logging the root we want to traverse consecutive commits
		 * even if they point at the same tree.
		 * But if we are looking for a specific path then we can avoid
		 * fetching packed commits which did not modify the path and
		 * only fetch their IDs. This speeds up 'got blame'.
		 */
		if (!got_path_is_root_dir(graph->path) &&
		    (commit->flags & GOT_COMMIT_FLAG_PACKED)) {
			int ncommits = 0;
			err = packed_first_parent_traversal(&ncommits,
			    graph, &qid->id, repo);
			if (err || ncommits > 0)
				return err;
		}
		return got_object_idset_add(graph->open_branches,
		    &qid->id, NULL);
	}

	/*
	 * If we are graphing commits for a specific path, skip branches
	 * which do not contribute any content to this path.
	 */
	if (commit->nparents > 1 && !got_path_is_root_dir(graph->path)) {
		err = got_object_id_by_path(&merged_id, repo, commit, graph->path);
		if (err && err->code != GOT_ERR_NO_TREE_ENTRY)
			return err;
		/* The requested path does not exist in this merge commit. */
	}
	if (commit->nparents > 1 && !got_path_is_root_dir(graph->path) &&
	    merged_id != NULL) {
		struct got_object_id *prev_id = NULL;
		int branches_differ = 0;


		STAILQ_FOREACH(qid, &commit->parent_ids, entry) {
			struct got_object_id *id = NULL;
			struct got_commit_object *pcommit = NULL;

			if (got_object_idset_contains(graph->open_branches,
			    &qid->id))
				continue;

			err = got_object_open_as_commit(&pcommit, repo,
			    &qid->id);
			if (err) {
				free(merged_id);
				free(prev_id);
				return err;
			}
			err = got_object_id_by_path(&id, repo, pcommit,
			    graph->path);
			got_object_commit_close(pcommit);
			pcommit = NULL;
			if (err) {
				if (err->code == GOT_ERR_NO_TREE_ENTRY) {
					branches_differ = 1;
					continue;
				}
				free(merged_id);
				free(prev_id);
				return err;
			}

			if (prev_id) {
				if (!branches_differ &&
				    got_object_id_cmp(id, prev_id) != 0)
					branches_differ = 1;
				free(prev_id);
			}
			prev_id = id;

			/*
			 * If a branch has created the merged content we can
			 * skip any other branches.
			 */
			if (got_object_id_cmp(merged_id, id) == 0) {
				err = got_object_idset_add(graph->open_branches,
				    &qid->id, NULL);
				free(merged_id);
				free(id);
				return err;
			}
		}

		free(prev_id);
		prev_id = NULL;
		free(merged_id);
		merged_id = NULL;

		/*
		 * If the path's content is the same on all branches,
		 * follow the first parent only.
		 */
		if (!branches_differ) {
			qid = STAILQ_FIRST(&commit->parent_ids);
			if (qid == NULL)
				return NULL;
			if (got_object_idset_contains(graph->open_branches,
			    &qid->id))
				return NULL;
			if (got_object_idset_contains(graph->node_ids,
			    &qid->id))
				return NULL; /* parent already traversed */
			return got_object_idset_add(graph->open_branches,
			    &qid->id, NULL);
		}
	}

	STAILQ_FOREACH(qid, &commit->parent_ids, entry) {
		if (got_object_idset_contains(graph->open_branches, &qid->id))
			continue;
		if (got_object_idset_contains(graph->node_ids, &qid->id))
			continue; /* parent already traversed */
		err = got_object_idset_add(graph->open_branches, &qid->id,
		    NULL);
		if (err)
			return err;
	}

	return NULL;
}

const struct got_error *
got_commit_graph_open(struct got_commit_graph **graph,
    const char *path, int first_parent_traversal)
{
	const struct got_error *err = NULL;

	*graph = calloc(1, sizeof(**graph));
	if (*graph == NULL)
		return got_error_from_errno("calloc");

	TAILQ_INIT(&(*graph)->iter_list);

	(*graph)->path = strdup(path);
	if ((*graph)->path == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

	(*graph)->node_ids = got_object_idset_alloc();
	if ((*graph)->node_ids == NULL) {
		err = got_error_from_errno("got_object_idset_alloc");
		goto done;
	}

	(*graph)->open_branches = got_object_idset_alloc();
	if ((*graph)->open_branches == NULL) {
		err = got_error_from_errno("got_object_idset_alloc");
		goto done;
	}

	if (first_parent_traversal)
		(*graph)->flags |= GOT_COMMIT_GRAPH_FIRST_PARENT_TRAVERSAL;
done:
	if (err) {
		got_commit_graph_close(*graph);
		*graph = NULL;
	}
	return err;
}

struct add_branch_tip_arg {
	struct got_commit_graph_branch_tip *tips;
	int ntips;
	struct got_repository *repo;
	struct got_commit_graph *graph;
};

static const struct got_error *
add_branch_tip(struct got_object_id *commit_id, void *data, void *arg)
{
	const struct got_error *err;
	struct add_branch_tip_arg *a = arg;
	struct got_commit_graph_node *new_node;
	struct got_commit_object *commit;

	err = got_object_open_as_commit(&commit, a->repo, commit_id);
	if (err)
		return err;

	err = add_node(&new_node, a->graph, commit_id, a->repo);
	if (err) {
		got_object_commit_close(commit);
		return err;
	}

	a->tips[a->ntips].commit_id = &new_node->id;
	a->tips[a->ntips].commit = commit;
	a->tips[a->ntips].new_node = new_node;
	a->ntips++;

	return NULL;
}

static const struct got_error *
fetch_commits_from_open_branches(struct got_commit_graph *graph,
    struct got_repository *repo, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err;
	struct add_branch_tip_arg arg;
	int i, ntips;

	ntips = got_object_idset_num_elements(graph->open_branches);
	if (ntips == 0)
		return NULL;

	/* (Re-)allocate branch tips array if necessary. */
	if (graph->ntips < ntips) {
		struct got_commit_graph_branch_tip *tips;
		tips = recallocarray(graph->tips, graph->ntips, ntips,
		    sizeof(*tips));
		if (tips == NULL)
			return got_error_from_errno("recallocarray");
		graph->tips = tips;
		graph->ntips = ntips;
	}
	arg.tips = graph->tips;
	arg.ntips = 0; /* add_branch_tip() will increment */
	arg.repo = repo;
	arg.graph = graph;
	err = got_object_idset_for_each(graph->open_branches, add_branch_tip,
	    &arg);
	if (err)
		goto done;

	for (i = 0; i < arg.ntips; i++) {
		struct got_object_id *commit_id;
		struct got_commit_object *commit;
		struct got_commit_graph_node *new_node;
		int changed;

		if (cancel_cb) {
			err = (*cancel_cb)(cancel_arg);
			if (err)
				break;
		}

		commit_id = arg.tips[i].commit_id;
		commit = arg.tips[i].commit;
		new_node = arg.tips[i].new_node;

		err = detect_changed_path(&changed, commit, commit_id,
		    graph->path, repo);
		if (err) {
			if (err->code != GOT_ERR_NO_OBJ)
				break;
			/*
			 * History of the path stops here on the current
			 * branch. Keep going on other branches.
			 */
			err = close_branch(graph, commit_id);
			if (err)
				break;
			continue;
		}
		if (changed) {
			add_node_to_iter_list(graph, new_node,
			    got_object_commit_get_committer_time(commit));
			arg.tips[i].new_node = NULL;
		}
		err = advance_branch(graph, commit_id, commit, repo);
		if (err)
			break;
	}
done:
	for (i = 0; i < arg.ntips; i++) {
		got_object_commit_close(arg.tips[i].commit);
		free(arg.tips[i].new_node);
	}
	return err;
}

void
got_commit_graph_close(struct got_commit_graph *graph)
{
	struct got_commit_graph_node *node;

	while ((node = TAILQ_FIRST(&graph->iter_list))) {
		TAILQ_REMOVE(&graph->iter_list, node, entry);
		free(node->more_parents);
		free(node);
	}

	if (graph->open_branches)
		got_object_idset_free(graph->open_branches);
	if (graph->node_ids)
		got_object_idset_free(graph->node_ids);
	free(graph->tips);
	free(graph->path);
	free(graph);
}

static const struct got_error *
remove_branch_tip(struct got_object_id *commit_id, void *data, void *arg)
{
	struct got_object_idset *open_branches = arg;

	return got_object_idset_remove(NULL, open_branches, commit_id);
}

const struct got_error *
got_commit_graph_iter_start(struct got_commit_graph *graph,
    struct got_object_id *id, struct got_repository *repo,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_commit_graph_node *node;

	/* First-parent traversal is implicitly topological. */
	graph->flags &= ~GOT_COMMIT_GRAPH_TOPOSORT;

	/* Clear left-over state from previous iteration attempts. */
	while ((node = TAILQ_FIRST(&graph->iter_list)))
		TAILQ_REMOVE(&graph->iter_list, node, entry);
	err = got_object_idset_for_each(graph->open_branches,
	    remove_branch_tip, graph->open_branches);
	if (err)
		return err;

	err = got_object_idset_add(graph->open_branches, id, NULL);
	if (err)
		return err;

	/* Locate first commit which changed graph->path. */
	while (TAILQ_EMPTY(&graph->iter_list) &&
	    got_object_idset_num_elements(graph->open_branches) > 0) {
		err = fetch_commits_from_open_branches(graph, repo,
		    cancel_cb, cancel_arg);
		if (err)
			return err;
	}

	if (TAILQ_EMPTY(&graph->iter_list)) {
		const char *path;
		if (got_path_is_root_dir(graph->path))
			return got_error_no_obj(id);
		path = graph->path;
		while (path[0] == '/')
			path++;
		return got_error_path(path, GOT_ERR_NO_TREE_ENTRY);
	}

	return NULL;
}

const struct got_error *
got_commit_graph_iter_next(struct got_object_id *id,
    struct got_commit_graph *graph, struct got_repository *repo,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_commit_graph_node *node, *pnode;
	int i;

	node = TAILQ_FIRST(&graph->iter_list);
	if (node == NULL) {
		/* We are done iterating, or iteration was not started. */
		return got_error(GOT_ERR_ITER_COMPLETED);
	}

	if (graph->flags & GOT_COMMIT_GRAPH_TOPOSORT) {
		/* At least one node with in-degree zero must exist. */
		while (node->indegree != 0)
			node = TAILQ_NEXT(node, entry);
	} else {
		while (TAILQ_NEXT(node, entry) == NULL &&
		    got_object_idset_num_elements(graph->open_branches) > 0) {
			err = fetch_commits_from_open_branches(graph, repo,
			    cancel_cb, cancel_arg);
			if (err)
				return err;
		}
	}

	memcpy(id, &node->id, sizeof(*id));

	TAILQ_REMOVE(&graph->iter_list, node, entry);
	if (graph->flags & GOT_COMMIT_GRAPH_TOPOSORT) {
		/* When visiting a commit decrement in-degree of all parents. */
		for (i = 0; i < node->nparents; i++) {
			if (i < nitems(node->parents))
				pnode = node->parents[i];
			else
				pnode = node->more_parents[i];
			pnode->indegree--;
		}
	}
	free(node);
	return NULL;
}

static const struct got_error *
find_yca_add_id(struct got_object_id **yca_id, struct got_commit_graph *graph,
    struct got_object_idset *commit_ids, struct got_repository *repo,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_object_id id;

	err = got_commit_graph_iter_next(&id, graph, repo, cancel_cb,
	    cancel_arg);
	if (err)
		return err;

	if (got_object_idset_contains(commit_ids, &id)) {
		*yca_id = got_object_id_dup(&id);
		if (*yca_id == NULL)
			err = got_error_from_errno("got_object_id_dup");
		return err;
	}

	return got_object_idset_add(commit_ids, &id, NULL);
}

/*
 * Sets *yca_id to the youngest common ancestor of commit_id and
 * commit_id2. Returns got_error(GOT_ERR_ANCESTRY) if they have no
 * common ancestors.
 *
 * If first_parent_traversal is nonzero, only linear history is considered.
 */
const struct got_error *
got_commit_graph_find_youngest_common_ancestor(struct got_object_id **yca_id,
    struct got_object_id *commit_id, struct got_object_id *commit_id2,
    int first_parent_traversal,
    struct got_repository *repo, got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_commit_graph *graph = NULL, *graph2 = NULL;
	int completed = 0, completed2 = 0;
	struct got_object_idset *commit_ids;

	*yca_id = NULL;

	commit_ids = got_object_idset_alloc();
	if (commit_ids == NULL)
		return got_error_from_errno("got_object_idset_alloc");

	err = got_commit_graph_open(&graph, "/", first_parent_traversal);
	if (err)
		goto done;

	err = got_commit_graph_open(&graph2, "/", first_parent_traversal);
	if (err)
		goto done;

	err = got_commit_graph_iter_start(graph, commit_id, repo,
	    cancel_cb, cancel_arg);
	if (err)
		goto done;

	err = got_commit_graph_iter_start(graph2, commit_id2, repo,
	    cancel_cb, cancel_arg);
	if (err)
		goto done;

	for (;;) {
		if (cancel_cb) {
			err = (*cancel_cb)(cancel_arg);
			if (err)
				break;
		}

		if (!completed) {
			err = find_yca_add_id(yca_id, graph, commit_ids, repo,
			    cancel_cb, cancel_arg);
			if (err) {
				if (err->code != GOT_ERR_ITER_COMPLETED)
					break;
				err = NULL;
				completed = 1;
			}
			if (*yca_id)
				break;
		}

		if (!completed2) {
			err = find_yca_add_id(yca_id, graph2, commit_ids, repo,
			    cancel_cb, cancel_arg);
			if (err) {
				if (err->code != GOT_ERR_ITER_COMPLETED)
					break;
				err = NULL;
				completed2 = 1;
			}
			if (*yca_id)
				break;
		}

		if (completed && completed2) {
			err = got_error(GOT_ERR_ANCESTRY);
			break;
		}
	}
done:
	got_object_idset_free(commit_ids);
	if (graph)
		got_commit_graph_close(graph);
	if (graph2)
		got_commit_graph_close(graph2);
	return err;
}

/*
 * Sort the graph for traversal in topological order.
 *
 * This implementation is based on the description of topological sorting
 * of git commits by Derrick Stolee at
 * https://github.blog/2022-08-30-gits-database-internals-ii-commit-history-queries/#topological-sorting
 * which reads as follows:
 *
 * The basic algorithm for topological sorting is Kahn’s algorithm which
 * follows two big steps:
 * 1. Walk all reachable commits, counting the number of times a commit appears
 * as a parent of another commit. Call these numbers the in-degree of the
 * commit, referencing the number of incoming edges.
 * 2. Walk the reachable commits, but only visit a commit if its in-degree
 * value is zero. When visiting a commit, decrement the in-degree value of
 * each parent.
 * 
 * This algorithm works because at least one of our starting points will
 * have in-degree zero, and then decrementing the in-degree value is similar
 * to deleting the commit from the graph, always having at least one commit
 * with in-degree zero.
 */
const struct got_error *
got_commit_graph_toposort(struct got_commit_graph *graph,
    struct got_object_id *id, struct got_repository *repo,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_commit_graph_node *node = NULL, *pnode = NULL;
	struct got_commit_object *commit = NULL;
	struct got_object_id_queue commits;
	const struct got_object_id_queue *parent_ids;
	struct got_object_qid *qid = NULL, *pid;
	int i;

	STAILQ_INIT(&commits);

	if (graph->flags & GOT_COMMIT_GRAPH_FIRST_PARENT_TRAVERSAL)
		return got_commit_graph_iter_start(graph, id, repo,
		    cancel_cb, cancel_arg);

	/* Clear left-over state from previous iteration attempts. */
	while ((node = TAILQ_FIRST(&graph->iter_list)))
		TAILQ_REMOVE(&graph->iter_list, node, entry);
	err = got_object_idset_for_each(graph->open_branches,
	    remove_branch_tip, graph->open_branches);
	if (err)
		return err;

	graph->flags |= GOT_COMMIT_GRAPH_TOPOSORT;

	/*
	 * Sorting the commit graph in topological order requires visiting
	 * every reachable commit. This is very expensive but there are
	 * ways to speed this up significantly in the future:
	 * 1) Run this loop in got-read-pack if possible.
	 * 2) Use Git's commit-graph file to compute the result incrementally.
	 *    See the blog post linked above for details.
	 */
	err = got_object_qid_alloc_partial(&qid);
	if (err)
		return err;
	memcpy(&qid->id, id, sizeof(qid->id));
	STAILQ_INSERT_TAIL(&commits, qid, entry);
	while (!STAILQ_EMPTY(&commits)) {
		if (cancel_cb) {
			err = (*cancel_cb)(cancel_arg);
			if (err)
				break;
		}

		qid = STAILQ_FIRST(&commits);
		STAILQ_REMOVE_HEAD(&commits, entry);
		err = got_object_open_as_commit(&commit, repo, &qid->id);
		if (err)
			break;

		node = got_object_idset_get(graph->node_ids, &qid->id);
		if (node == NULL) {
			err = add_node(&node, graph, id, repo);
			if (err)
				break;
			TAILQ_INSERT_TAIL(&graph->iter_list, node, entry);
		}

		got_object_qid_free(qid);
		qid = NULL;

		if (node->timestamp != 0) /* already traversed once */
			continue;

		if (node->nparents == -1) {
			node->nparents = got_object_commit_get_nparents(commit);
			if (node->nparents > nitems(node->parents)) {
				node->more_parents = calloc(node->nparents,
				    sizeof(*node->more_parents));
				if (node->more_parents == NULL) {
					err = got_error_from_errno("calloc");
					break;
				}
			}

		}

		node->timestamp = got_object_commit_get_committer_time(commit);
		parent_ids = got_object_commit_get_parent_ids(commit);
		i = 0;
		STAILQ_FOREACH(pid, parent_ids, entry) {
			if (cancel_cb) {
				err = (*cancel_cb)(cancel_arg);
				if (err)
					goto done;
			}

			/*
			 * Increment the in-degree counter every time a given
			 * commit appears as the parent of another commit.
			 */
			pnode = got_object_idset_get(graph->node_ids, &pid->id);
			if (pnode == NULL) {
				err = add_node(&pnode, graph, &pid->id, repo);
				if (err)
					goto done;
				TAILQ_INSERT_TAIL(&graph->iter_list, pnode,
				    entry);
			}
			pnode->indegree++;

			/*
			 * Cache parent pointers on the node to make future
			 * in-degree updates easier.
			 */
			if (node->nparents <= nitems(node->parents)) {
				node->parents[i] = pnode;
			} else {
				node->more_parents[i] = pnode;
				if (i < nitems(node->parents))
					node->parents[i] = pnode;
			}
			i++;

			/* Keep traversing through all parent commits. */
			err = got_object_qid_alloc_partial(&qid);
			if (err)
				goto done;
			memcpy(&qid->id, &pid->id, sizeof(qid->id));
			STAILQ_INSERT_TAIL(&commits, qid, entry);
			qid = NULL;
		}

		got_object_commit_close(commit);
		commit = NULL;
	}
done:
	if (commit)
		got_object_commit_close(commit);
	got_object_qid_free(qid);
	got_object_id_queue_free(&commits);
	return err;
}
