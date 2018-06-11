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
#include "got_lib_zbuf.h"
#include "got_lib_object.h"
#include "got_lib_object_idset.h"

struct got_commit_graph_node {
	struct got_object_id id;

	/*
	 * Each graph node corresponds to a commit object.
	 * Graph vertices are modelled with two separate adjacency lists:
	 * Adjacencies of a graph node are either parent (older) commits,
	 * and child (younger) commits.
	 */
	int nparents;
	struct got_object_id_queue parent_ids;
	int nchildren;
	struct got_object_id_queue child_ids;

	time_t commit_timestamp;

	/* Used during graph iteration. */
	TAILQ_ENTRY(got_commit_graph_node) entry;
};

struct got_commit_graph {
	/* The set of all commits we have traversed. */
	struct got_object_idset *node_ids;

	/* The commit at which traversal began (youngest commit in node_ids). */
	struct got_commit_graph_node *head_node;

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

	/* The next commit to return when the API user asks for one. */
	struct got_commit_graph_node *iter_node;

	TAILQ_HEAD(, got_commit_graph_node) iter_candidates;
};

static struct got_commit_graph *
alloc_graph(void)
{
	struct got_commit_graph *graph;

	graph = calloc(1, sizeof(*graph));
	if (graph == NULL)
		return NULL;

	graph->node_ids = got_object_idset_alloc();
	if (graph->node_ids == NULL) {
		free(graph);
		return NULL;
	}

	graph->open_branches = got_object_idset_alloc();
	if (graph->open_branches == NULL) {
		got_object_idset_free(graph->node_ids);
		free(graph);
		return NULL;
	}

	TAILQ_INIT(&graph->iter_candidates);
	return graph;
}

#if 0
static int
is_head_node(struct got_commit_graph_node *node)
{
	return node->nchildren == 0;
}

static int
is_merge_point(struct got_commit_graph_node *node)
{
	return node->nparents > 1;
}

int
is_branch_point(struct got_commit_graph_node *node)
{
	return node->nchildren > 1;
}
#endif

static int
is_root_node(struct got_commit_graph_node *node)
{
	return node->nparents == 0;
}

static void
add_iteration_candidate(struct got_commit_graph *graph,
    struct got_commit_graph_node *node)
{
	struct got_commit_graph_node *n, *next;
	
	if (TAILQ_EMPTY(&graph->iter_candidates)) {
		TAILQ_INSERT_TAIL(&graph->iter_candidates, node, entry);
		return;
	}

	TAILQ_FOREACH(n, &graph->iter_candidates, entry) {
		if (node->commit_timestamp < n->commit_timestamp) {
			next = TAILQ_NEXT(n, entry);
			if (next == NULL) {
				TAILQ_INSERT_AFTER(&graph->iter_candidates, n,
				    node, entry);
				break;
			}
			if (node->commit_timestamp >= next->commit_timestamp) {
				TAILQ_INSERT_BEFORE(next, node, entry);
				break;
			}
		} else {
			TAILQ_INSERT_BEFORE(n, node, entry);
			break;
		}
	}
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
		free(qid);
		return err;
	}

	SIMPLEQ_INSERT_TAIL(ids, qid, entry);
	return NULL;
}

static const struct got_error *
add_node(struct got_commit_graph_node **new_node,
    struct got_commit_graph *graph, struct got_object_id *commit_id,
    struct got_commit_object *commit, struct got_object_id *child_commit_id)
{
	const struct got_error *err = NULL;
	struct got_commit_graph_node *node, *existing_node;
	struct got_object_qid *qid;

	*new_node = NULL;

	node = calloc(1, sizeof(*node));
	if (node == NULL)
		return got_error_from_errno();

	memcpy(&node->id, commit_id, sizeof(node->id));
	SIMPLEQ_INIT(&node->parent_ids);
	SIMPLEQ_INIT(&node->child_ids);
	SIMPLEQ_FOREACH(qid, &commit->parent_ids, entry) {
		err = add_vertex(&node->parent_ids, qid->id);
		if (err)
			return err;
		node->nparents++;
	}
	node->commit_timestamp = commit->committer_time; /* XXX not UTC! */

	err = got_object_idset_add((void **)(&existing_node),
	    graph->node_ids, &node->id, node);
	if (err == NULL) {
		struct got_object_qid *qid;

		add_iteration_candidate(graph, node);
		err = got_object_idset_remove(graph->open_branches, commit_id);
		if (err && err->code != GOT_ERR_NO_OBJ)
			return err;
		SIMPLEQ_FOREACH(qid, &commit->parent_ids, entry) {
			if (got_object_idset_get(graph->node_ids, qid->id))
				continue; /* parent already traversed */
			err = got_object_idset_add(NULL, graph->open_branches,
			    qid->id, node);
			if (err && err->code != GOT_ERR_OBJ_EXISTS)
				return err;
		}
		*new_node = node;
	} else if (err->code == GOT_ERR_OBJ_EXISTS) {
		err = NULL;
		free(node);
		node = existing_node;
	} else {
		free(node);
		return err;
	}

	if (child_commit_id) {
		struct got_object_qid *cid;

		/* Prevent linking to self. */
		if (got_object_id_cmp(commit_id, child_commit_id) == 0)
			return got_error(GOT_ERR_BAD_OBJ_ID);

		/* Prevent double-linking to the same child. */
		SIMPLEQ_FOREACH(cid, &node->child_ids, entry) {
			if (got_object_id_cmp(cid->id, child_commit_id) == 0)
				return got_error(GOT_ERR_BAD_OBJ_ID);
		}

		err = add_vertex(&node->child_ids, child_commit_id);
		if (err)
			return err;
		node->nchildren++;

	}

	return err;
}

const struct got_error *
got_commit_graph_open(struct got_commit_graph **graph,
    struct got_object_id *commit_id, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	struct got_commit_object *commit;

	*graph = NULL;

	err = got_object_open_as_commit(&commit, repo, commit_id);
	if (err)
		return err;

	*graph = alloc_graph();
	if (*graph == NULL) {
		got_object_commit_close(commit);
		return got_error_from_errno();
	}

	err = add_node(&(*graph)->head_node, *graph, commit_id, commit, NULL);
	got_object_commit_close(commit);
	if (err) {
		got_commit_graph_close(*graph);
		*graph = NULL;
		return err;
	}
	
	return NULL;
}

struct got_commit_graph_branch {
	struct got_object_id parent_id;
	struct got_commit_graph_node *node;
};

struct gather_branches_arg {
	struct got_commit_graph_branch *branches;
	int nbranches;
};

static void
gather_branches(struct got_object_id *id, void *data, void *arg)
{
	struct gather_branches_arg *a = arg;
	memcpy(&a->branches[a->nbranches].parent_id, id, sizeof(*id));
	a->branches[a->nbranches].node = data;
	a->nbranches++;
}

const struct got_error *
fetch_commits_from_open_branches(int *ncommits,
    struct got_commit_graph *graph, struct got_repository *repo)
{
	const struct got_error *err;
	struct got_commit_graph_branch *branches;
	struct gather_branches_arg arg;
	int i;

	*ncommits = 0;

	arg.nbranches = got_object_idset_num_elements(graph->open_branches);
	if (arg.nbranches == 0)
		return NULL;

	/*
	 * Adding nodes to the graph might change the graph's open
	 * branches state. Create a local copy of the current state.
	 */
	branches = calloc(arg.nbranches, sizeof(*branches));
	if (branches == NULL)
		return got_error_from_errno();
	arg.nbranches = 0; /* reset; gather_branches() will increment */
	arg.branches = branches;
	got_object_idset_for_each(graph->open_branches, gather_branches, &arg);

	for (i = 0; i < arg.nbranches; i++) {
		struct got_object_id *commit_id;
		struct got_commit_graph_node *child_node, *new_node;
		struct got_commit_object *commit;

		commit_id = &branches[i].parent_id;
		child_node = branches[i].node;

		err = got_object_open_as_commit(&commit, repo, commit_id);
		if (err)
			break;

		err = add_node(&new_node, graph, commit_id, commit,
		    &child_node->id);
		got_object_commit_close(commit);
		if (err) {
			if (err->code != GOT_ERR_OBJ_EXISTS)
				break;
			err = NULL;
		}
		if (new_node)
			(*ncommits)++;
	}

	free(branches);
	return err;
}

const struct got_error *
got_commit_graph_fetch_commits(int *nfetched, struct got_commit_graph *graph,
    int limit, struct got_repository *repo)
{
	const struct got_error *err;
	int total = 0, ncommits;

	*nfetched = 0;

	while (total < limit) {
		err = fetch_commits_from_open_branches(&ncommits, graph, repo);
		if (err)
			return err;
		if (ncommits == 0)
			break;
		total += ncommits;
	}

	*nfetched = total;
	return NULL;
}

static void
free_graph_node(struct got_object_id *id, void *data, void *arg)
{
	struct got_commit_graph_node *node = data;
	while (!SIMPLEQ_EMPTY(&node->child_ids)) {
		struct got_object_qid *child = SIMPLEQ_FIRST(&node->child_ids);
		SIMPLEQ_REMOVE_HEAD(&node->child_ids, entry);
		free(child);
	}
	free(node);
}

void
got_commit_graph_close(struct got_commit_graph *graph)
{
	got_object_idset_free(graph->open_branches);
	got_object_idset_for_each(graph->node_ids, free_graph_node, NULL);
	got_object_idset_free(graph->node_ids);
	free(graph);
}

const struct got_error *
got_commit_graph_iter_start(struct got_commit_graph *graph,
    struct got_object_id *id)
{
	struct got_commit_graph_node *start_node, *node;
	struct got_object_qid *qid;

	start_node = got_object_idset_get(graph->node_ids, id);
	if (start_node == NULL)
		return got_error(GOT_ERR_NO_OBJ);

	graph->iter_node = start_node;

	while (!TAILQ_EMPTY(&graph->iter_candidates)) {
		node = TAILQ_FIRST(&graph->iter_candidates);
		TAILQ_REMOVE(&graph->iter_candidates, node, entry);
	}

	/* Put all known parents of this commit on the candidate list. */
	SIMPLEQ_FOREACH(qid, &start_node->parent_ids, entry) {
		node = got_object_idset_get(graph->node_ids, qid->id);
		if (node)
			add_iteration_candidate(graph, node);
	}

	return NULL;
}

const struct got_error *
got_commit_graph_iter_next(struct got_object_id **id,
    struct got_commit_graph *graph)
{
	struct got_commit_graph_node *node;

	if (graph->iter_node == NULL) {
		/* We are done interating, or iteration was not started. */
		*id = NULL;
		return NULL;
	}

	if (TAILQ_EMPTY(&graph->iter_candidates)) {
		if (is_root_node(graph->iter_node) &&
		    got_object_idset_num_elements(graph->open_branches) == 0) {
			*id = &graph->iter_node->id;
			/* We are done interating. */
			graph->iter_node = NULL;
			return NULL;
		}
		return got_error(GOT_ERR_ITER_NEED_MORE);
	}

	*id = &graph->iter_node->id;
	node = TAILQ_FIRST(&graph->iter_candidates);
	TAILQ_REMOVE(&graph->iter_candidates, node, entry);
	graph->iter_node = node;
	return NULL;
}

int
got_commit_graph_contains_object(struct got_commit_graph *graph,
    struct got_object_id *id)
{
	return (got_object_idset_get(graph->node_ids, id) != NULL);
}
