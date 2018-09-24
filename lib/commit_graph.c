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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/stdint.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sha1.h>
#include <zlib.h>
#include <ctype.h>

#include "got_error.h"
#include "got_object.h"
#include "got_commit_graph.h"

#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_object_idset.h"
#include "got_lib_path.h"

struct got_commit_graph_node {
	struct got_object_id id;

	/*
	 * Each graph node corresponds to a commit object.
	 * Graph vertices are modelled with an adjacency list.
	 * Adjacencies of a graph node are parent (older) commits.
	 */
	int nparents;
	struct got_object_id_queue parent_ids;

	time_t commit_timestamp;

	/* Used during graph iteration. */
	TAILQ_ENTRY(got_commit_graph_node) entry;
};

TAILQ_HEAD(got_commit_graph_iter_list, got_commit_graph_node);

struct got_commit_graph_branch_tip {
	struct got_object_id id;
	struct got_commit_graph_node *node;
};

struct got_commit_graph {
	/* The set of all commits we have traversed. */
	struct got_object_idset *node_ids;

	/* The commit at which traversal began (youngest commit in node_ids). */
	struct got_commit_graph_node *head_node;

	int flags;
#define GOT_COMMIT_GRAPH_FIRST_PARENT_TRAVERSAL		0x01

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

	/* Copy of known branch tips for fetch_commits_from_open_branches(). */
	struct got_commit_graph_branch_tip *tips;
	size_t ntips;
#define GOT_COMMIT_GRAPH_MIN_TIPS 10	/* minimum amount of tips to allocate */

	/* Path of tree entry of interest to the API user. */
	char *path;

	/* The next commit to return when the API user asks for one. */
	struct got_commit_graph_node *iter_node;

	/* The graph iteration list contains all nodes in sorted order. */
	struct got_commit_graph_iter_list iter_list;
};

static struct got_commit_graph *
alloc_graph(const char *path)
{
	struct got_commit_graph *graph;

	graph = calloc(1, sizeof(*graph));
	if (graph == NULL)
		return NULL;

	graph->path = strdup(path);
	if (graph->path == NULL) {
		free(graph);
		return NULL;
	}

	graph->node_ids = got_object_idset_alloc();
	if (graph->node_ids == NULL) {
		free(graph->path);
		free(graph);
		return NULL;
	}

	graph->open_branches = got_object_idset_alloc();
	if (graph->open_branches == NULL) {
		got_object_idset_free(graph->node_ids);
		free(graph->path);
		free(graph);
		return NULL;
	}

	TAILQ_INIT(&graph->iter_list);
	return graph;
}

#if 0
static int
is_head_node(struct got_commit_graph_node *node)
{
	return node->nchildren == 0;
}

int
is_branch_point(struct got_commit_graph_node *node)
{
	return node->nchildren > 1;
}

static int
is_root_node(struct got_commit_graph_node *node)
{
	return node->nparents == 0;
}
#endif

static int
is_merge_point(struct got_commit_graph_node *node)
{
	return node->nparents > 1;
}

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

	err = got_object_open_as_tree(&tree, repo, commit->tree_id);
	if (err)
		return err;

	pid = SIMPLEQ_FIRST(&commit->parent_ids);
	if (pid == NULL) {
		struct got_object_id *obj_id;
		err = got_object_id_by_path(&obj_id, repo, commit_id, path);
		if (err)
			err = NULL;
		else
			*changed = 1;
		free(obj_id);
		goto done;
	}

	err = got_object_open_as_commit(&pcommit, repo, pid->id);
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
    struct got_commit_graph_node *node,
    struct got_commit_graph_node *child_node)
{
	struct got_commit_graph_node *n, *next;

	if (TAILQ_EMPTY(&graph->iter_list)) {
		TAILQ_INSERT_HEAD(&graph->iter_list, node, entry);
		graph->iter_node = node;
		return;
	}

	n = graph->iter_node;
	/* Ensure that an iteration in progress will see this new commit. */
	while (n) {
		next = TAILQ_NEXT(n, entry);
		if (next && node->commit_timestamp >= next->commit_timestamp) {
			TAILQ_INSERT_BEFORE(next, node, entry);
			return;
		}
		n = next;
	}
	TAILQ_INSERT_TAIL(&graph->iter_list, node, entry);
}

static const struct got_error *
add_vertex(struct got_object_id_queue *ids, struct got_object_id *id)
{
	struct got_object_qid *qid;

	qid = calloc(1, sizeof(*qid));
	if (qid == NULL)
		return got_error_from_errno();

	qid->id = got_object_id_dup(id);
	if (qid->id == NULL) {
		const struct got_error *err = got_error_from_errno();
		got_object_qid_free(qid);
		return err;
	}

	SIMPLEQ_INSERT_TAIL(ids, qid, entry);
	return NULL;
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
advance_branch(struct got_commit_graph *graph,
    struct got_commit_graph_node *node,
    struct got_object_id *commit_id, struct got_commit_object *commit,
    struct got_repository *repo)
{
	const struct got_error *err;
	struct got_object_qid *qid;

	err = close_branch(graph, commit_id);
	if (err)
		return err;

	if (graph->flags & GOT_COMMIT_GRAPH_FIRST_PARENT_TRAVERSAL) {
		qid = SIMPLEQ_FIRST(&commit->parent_ids);
		if (qid == NULL)
			return NULL;
		err = got_object_idset_add(NULL, graph->open_branches, qid->id,
		    node);
		if (err && err->code != GOT_ERR_OBJ_EXISTS)
			return err;
		return NULL;
	}

	/*
	 * If we are graphing commits for a specific path, skip branches
	 * which do not contribute any content to this path.
	 */
	if (is_merge_point(node) && !got_path_is_root_dir(graph->path)) {
		struct got_object_id *id, *merged_id, *prev_id = NULL;
		int branches_differ = 0;

		err = got_object_id_by_path(&merged_id, repo, commit_id,
		    graph->path);
		if (err)
			return err;

		SIMPLEQ_FOREACH(qid, &commit->parent_ids, entry) {
			if (got_object_idset_get(graph->node_ids, qid->id))
				continue; /* parent already traversed */

			err = got_object_id_by_path(&id, repo, qid->id,
			    graph->path);
			if (err) {
				if (err->code == GOT_ERR_NO_OBJ) {
					branches_differ = 1;
					continue;
				}
				return err;
			}

			if (prev_id) {
				if (!branches_differ &&
				    got_object_id_cmp(merged_id, prev_id) != 0)
					branches_differ = 1;
			} else
				prev_id = id;

			/*
			 * If a branch has created the merged content we can
			 * skip any other branches.
			 */
			if (got_object_id_cmp(merged_id, id) == 0) {
				err = got_object_idset_add(NULL,
				    graph->open_branches, qid->id, node);
				if (err && err->code != GOT_ERR_OBJ_EXISTS)
					return err;
				return NULL;
			}
		}

		/*
		 * If the path's content is the same on all branches,
		 * follow the first parent only.
		 */
		if (!branches_differ) {
			qid = SIMPLEQ_FIRST(&commit->parent_ids);
			if (qid == NULL)
				return NULL;
			if (got_object_idset_get(graph->node_ids, qid->id))
				return NULL; /* parent already traversed */
			err = got_object_idset_add(NULL,
			    graph->open_branches, qid->id, node);
			if (err && err->code != GOT_ERR_OBJ_EXISTS)
				return err;
			return NULL;
		}
	}

	SIMPLEQ_FOREACH(qid, &commit->parent_ids, entry) {
		if (got_object_idset_get(graph->node_ids, qid->id))
			continue; /* parent already traversed */
		err = got_object_idset_add(NULL, graph->open_branches,
		    qid->id, node);
		if (err && err->code != GOT_ERR_OBJ_EXISTS)
			return err;
	}

	return NULL;
}

static void
free_node(struct got_commit_graph_node *node)
{
	while (!SIMPLEQ_EMPTY(&node->parent_ids)) {
		struct got_object_qid *pid = SIMPLEQ_FIRST(&node->parent_ids);
		SIMPLEQ_REMOVE_HEAD(&node->parent_ids, entry);
		got_object_qid_free(pid);
	}
	free(node);
}

static const struct got_error *
add_node(struct got_commit_graph_node **new_node,
    struct got_commit_graph *graph, struct got_object_id *commit_id,
    struct got_commit_object *commit, struct got_commit_graph_node *child_node,
    struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_commit_graph_node *node;
	struct got_object_qid *pid;
	int changed = 0, branch_done = 0;

	*new_node = NULL;

	node = calloc(1, sizeof(*node));
	if (node == NULL)
		return got_error_from_errno();

	memcpy(&node->id, commit_id, sizeof(node->id));
	SIMPLEQ_INIT(&node->parent_ids);
	SIMPLEQ_FOREACH(pid, &commit->parent_ids, entry) {
		err = add_vertex(&node->parent_ids, pid->id);
		if (err) {
			free_node(node);
			return err;
		}
		node->nparents++;
	}

	err = got_object_idset_add(NULL, graph->node_ids, &node->id, node);
	if (err) {
		if (err->code == GOT_ERR_OBJ_EXISTS)
			err = NULL;
		free_node(node);
		return err;
	}

	err = detect_changed_path(&changed, commit, commit_id, graph->path,
	    repo);
	if (err) {
		if (err->code == GOT_ERR_NO_OBJ) {
			/*
			 * History of the path stops here on the current
			 * branch. Keep going on other branches.
			 */
			err = NULL;
			branch_done = 1;
		} else {
			free_node(node);
			return err;
		}
	}

	node->commit_timestamp = mktime(&commit->tm_committer);
	if (node->commit_timestamp == -1) {
		free_node(node);
		return got_error_from_errno();
	}

	if (changed && !is_merge_point(node))
		add_node_to_iter_list(graph, node, child_node);

	if (branch_done)
		err = close_branch(graph, commit_id);
	else
		err = advance_branch(graph, node, commit_id, commit, repo);
	if (err)
		free_node(node);
	else
		*new_node = node;

	return err;
}

const struct got_error *
got_commit_graph_open(struct got_commit_graph **graph,
    struct got_object_id *commit_id, const char *path,
    int first_parent_traversal, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_commit_object *commit;

	*graph = NULL;

	err = got_object_open_as_commit(&commit, repo, commit_id);
	if (err)
		return err;

	/* The path must exist in our initial commit. */
	if (!got_path_is_root_dir(path)) {
		struct got_object_id *obj_id;
		err = got_object_id_by_path(&obj_id, repo, commit_id, path);
		if (err)
			return err;
		free(obj_id);
	}

	*graph = alloc_graph(path);
	if (*graph == NULL) {
		got_object_commit_close(commit);
		return got_error_from_errno();
	}

	if (first_parent_traversal)
		(*graph)->flags |= GOT_COMMIT_GRAPH_FIRST_PARENT_TRAVERSAL;

	err = add_node(&(*graph)->head_node, *graph, commit_id, commit, NULL,
	    repo);
	got_object_commit_close(commit);
	if (err) {
		got_commit_graph_close(*graph);
		*graph = NULL;
		return err;
	}
	
	return NULL;
}

struct gather_branch_tips_arg {
	struct got_commit_graph_branch_tip *tips;
	int ntips;
};

static void
gather_branch_tips(struct got_object_id *id, void *data, void *arg)
{
	struct gather_branch_tips_arg *a = arg;
	memcpy(&a->tips[a->ntips].id, id, sizeof(*id));
	a->tips[a->ntips].node = data;
	a->ntips++;
}

static const struct got_error *
fetch_commits_from_open_branches(int *ncommits, int *wanted_id_added,
    struct got_object_id **changed_id, struct got_commit_graph *graph,
    struct got_repository *repo, struct got_object_id *wanted_id)
{
	const struct got_error *err;
	struct gather_branch_tips_arg arg;
	int i;

	*ncommits = 0;
	if (wanted_id_added)
		*wanted_id_added = 0;
	if (changed_id)
		*changed_id = NULL;

	arg.ntips = got_object_idset_num_elements(graph->open_branches);
	if (arg.ntips == 0)
		return NULL;

	/*
	 * Adding nodes to the graph might change the graph's open
	 * branches state. Create a local copy of the current state.
	 */
	if (graph->ntips < arg.ntips) {
		struct got_commit_graph_branch_tip *tips;
		if (arg.ntips < GOT_COMMIT_GRAPH_MIN_TIPS)
			arg.ntips = GOT_COMMIT_GRAPH_MIN_TIPS;
		tips = reallocarray(graph->tips, arg.ntips, sizeof(*tips));
		if (tips == NULL)
			return got_error_from_errno();
		graph->tips = tips;
		graph->ntips = arg.ntips;
	}
	arg.ntips = 0; /* reset; gather_branch_tips() will increment */
	arg.tips = graph->tips;
	got_object_idset_for_each(graph->open_branches,
	    gather_branch_tips, &arg);

	for (i = 0; i < arg.ntips; i++) {
		struct got_object_id *commit_id;
		struct got_commit_graph_node *child_node, *new_node;
		struct got_commit_object *commit;
		int changed;

		commit_id = &graph->tips[i].id;
		child_node = graph->tips[i].node;

		err = got_object_open_as_commit(&commit, repo, commit_id);
		if (err)
			break;

		err = detect_changed_path(&changed, commit, commit_id,
		    graph->path, repo);
		if (err) {
			got_object_commit_close(commit);
			if (err->code != GOT_ERR_NO_OBJ)
				break;
			err = close_branch(graph, commit_id);
			if (err)
				break;
			continue;
		}
		if (changed && changed_id && *changed_id == NULL)
			*changed_id = commit_id;
		err = add_node(&new_node, graph, commit_id, commit, child_node,
		    repo);
		got_object_commit_close(commit);
		if (err)
			break;
		if (new_node)
			(*ncommits)++;
		if (wanted_id && got_object_id_cmp(commit_id, wanted_id) == 0)
			*wanted_id_added = 1;
	}

	return err;
}

const struct got_error *
got_commit_graph_fetch_commits(struct got_commit_graph *graph, int limit,
    struct got_repository *repo)
{
	const struct got_error *err;
	int nfetched = 0, ncommits;
	struct got_object_id *changed_id = NULL;

	while (nfetched < limit) {
		err = fetch_commits_from_open_branches(&ncommits, NULL,
		    &changed_id, graph, repo, NULL);
		if (err)
			return err;
		if (ncommits == 0)
			break;
		if (changed_id)
			nfetched += ncommits;
	}

	return NULL;
}

static void
free_node_iter(struct got_object_id *id, void *data, void *arg)
{
	struct got_commit_graph_node *node = data;
	free_node(node);
}

void
got_commit_graph_close(struct got_commit_graph *graph)
{
	got_object_idset_free(graph->open_branches);
	got_object_idset_for_each(graph->node_ids, free_node_iter, NULL);
	got_object_idset_free(graph->node_ids);
	free(graph->tips);
	free(graph->path);
	free(graph);
}

const struct got_error *
got_commit_graph_iter_start(struct got_commit_graph *graph,
    struct got_object_id *id, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_commit_graph_node *start_node;
	struct got_commit_object *commit;
	int changed;

	start_node = got_object_idset_get(graph->node_ids, id);
	if (start_node == NULL)
		return got_error(GOT_ERR_NO_OBJ);

	err = got_object_open_as_commit(&commit, repo, &start_node->id);
	if (err)
		return err;

	err = detect_changed_path(&changed, commit, &start_node->id,
	    graph->path, repo);
	if (err) {
		got_object_commit_close(commit);
		return err;
	}

	if (!changed) {
		/* Locate first commit which changed graph->path. */
		struct got_object_id *changed_id = NULL;
		while (changed_id == NULL) {
			int ncommits;
			err = fetch_commits_from_open_branches(&ncommits, NULL,
			    &changed_id, graph, repo, NULL);
			if (err) {
				got_object_commit_close(commit);
				return err;
			}
		}
		start_node = got_object_idset_get(graph->node_ids, changed_id);
	}
	got_object_commit_close(commit);

	graph->iter_node = start_node;
	return NULL;
}

const struct got_error *
got_commit_graph_iter_next(struct got_object_id **id,
    struct got_commit_graph *graph)
{
	*id = NULL;

	if (graph->iter_node == NULL) {
		/* We are done iterating, or iteration was not started. */
		return got_error(GOT_ERR_ITER_COMPLETED);
	}

	if (graph->iter_node ==
	    TAILQ_LAST(&graph->iter_list, got_commit_graph_iter_list) &&
	    got_object_idset_num_elements(graph->open_branches) == 0) {
		/* We are done iterating. */
		*id = &graph->iter_node->id;
		graph->iter_node = NULL;
		return NULL;
	}

	if (TAILQ_NEXT(graph->iter_node, entry) == NULL)
		return got_error(GOT_ERR_ITER_NEED_MORE);

	*id = &graph->iter_node->id;
	graph->iter_node = TAILQ_NEXT(graph->iter_node, entry);
	return NULL;
}
