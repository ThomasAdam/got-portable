/*
 * Copyright (c) 2023 Mark Jamsek <mark@jamsek.dev>
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

#include "got_compat.h"

#include <sys/queue.h>

#include <ctype.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "got_reference.h"
#include "got_error.h"
#include "got_object.h"
#include "got_repository.h"
#include "got_cancel.h"
#include "got_worktree.h"
#include "got_commit_graph.h"
#include "got_keyword.h"

struct keyword_mod {
	char		*kw;
	uint64_t	 n;
	uint8_t		 sym;
	uint8_t		 iskeyword;
	uint8_t		 ismodified;
};

#define GOT_KEYWORD_DESCENDANT	'+'
#define GOT_KEYWORD_ANCESTOR	'-'

static const struct got_error *
parse_keyword(struct keyword_mod *kwm, const char *keyword)
{
	const char	*kw;
	char		*p;

	if (keyword == NULL)
		return NULL;

	/* check if it is a (modified) keyword or modified reference */
	if (*keyword == ':') {
		kwm->iskeyword = 1;
		kw = keyword + 1;
	} else
		kw = keyword;

	kwm->kw = strdup(kw);
	if (kwm->kw == NULL)
		return got_error_from_errno("strdup");

	p = strchr(kwm->kw, ':');

	if (p != NULL) {
		*p = '\0';
		++p;
		if (*p != GOT_KEYWORD_DESCENDANT && *p != GOT_KEYWORD_ANCESTOR)
			return got_error_fmt(GOT_ERR_BAD_KEYWORD,
			    "'%s'", keyword);

		kwm->ismodified = 1;
		kwm->sym = *p;
		++p;

		if (*p) {
			const char	*errstr;
			long long	 n;

			n = strtonum(p, 0, LLONG_MAX, &errstr);
			if (errstr != NULL)
				return got_error_fmt(GOT_ERR_BAD_KEYWORD,
				    "'%s'", keyword);

			kwm->n = n;
		} else
			kwm->n = 1;	/* :(+/-) == :(+/-)1 */
	}

	return NULL;
}

const struct got_error *
got_keyword_to_idstr(char **ret, const char *keyword,
    struct got_repository *repo, struct got_worktree *wt)
{
	const struct got_error		*err = NULL;
	struct got_commit_graph		*graph = NULL;
	struct got_object_id		*head_id = NULL, *kwid = NULL;
	struct got_object_id		 iter_id;
	struct got_reflist_head		 refs;
	struct got_object_id_queue	 commits;
	struct got_object_qid		*qid;
	struct keyword_mod		 kwm;
	const char			*kw = NULL;
	char				*kwid_str = NULL;
	uint64_t			 n = 0;

	*ret = NULL;
	TAILQ_INIT(&refs);
	STAILQ_INIT(&commits);
	memset(&kwm, 0, sizeof(kwm));

	err = parse_keyword(&kwm, keyword);
	if (err != NULL)
		goto done;

	kw = kwm.kw;

	if (kwm.iskeyword) {
		if (strcmp(kw, GOT_KEYWORD_BASE) == 0) {
			if (wt == NULL) {
				err = got_error_msg(GOT_ERR_NOT_WORKTREE,
				    "'-c :base' requires work tree");
				goto done;
			}

			err = got_object_id_str(&kwid_str,
			    got_worktree_get_base_commit_id(wt));
			if (err != NULL)
				goto done;
		} else if (strcmp(kw, GOT_KEYWORD_HEAD) == 0) {
			struct got_reference *head_ref;

			err = got_ref_open(&head_ref, repo, wt != NULL ?
			    got_worktree_get_head_ref_name(wt) :
			    GOT_REF_HEAD, 0);
			if (err != NULL)
				goto done;

			kwid_str = got_ref_to_str(head_ref);
			got_ref_close(head_ref);
			if (kwid_str == NULL) {
				err = got_error_from_errno("got_ref_to_str");
				goto done;
			}
		} else {
			err = got_error_fmt(GOT_ERR_BAD_KEYWORD, "'%s'", kw);
			goto done;
		}
	} else if (kwm.ismodified) {
		/* reference:[(+|-)[N]] */
		kwid_str = strdup(kw);
		if (kwid_str == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
	} else
		goto done;

	if (kwm.n == 0)
		goto done;	/* unmodified keyword */

	err = got_ref_list(&refs, repo, NULL, got_ref_cmp_by_name, NULL);
	if (err)
		goto done;

	err = got_repo_match_object_id(&kwid, NULL, kwid_str,
	    GOT_OBJ_TYPE_COMMIT, &refs, repo);
	if (err != NULL)
		goto done;

	/*
	 * If looking for a descendant, we need to iterate from
	 * HEAD so grab its id now if it's not already in kwid.
	 */
	if (kwm.sym == GOT_KEYWORD_DESCENDANT && kw != NULL &&
	    strcmp(kw, GOT_KEYWORD_HEAD) != 0) {
		struct got_reference *head_ref;

		err = got_ref_open(&head_ref, repo, wt != NULL ?
		    got_worktree_get_head_ref_name(wt) : GOT_REF_HEAD, 0);
		if (err != NULL)
			goto done;
		err = got_ref_resolve(&head_id, repo, head_ref);
		got_ref_close(head_ref);
		if (err != NULL)
			goto done;
	}

	err = got_commit_graph_open(&graph, "/", 1);
	if (err)
		goto done;

	err = got_commit_graph_iter_start(graph,
	    head_id != NULL ? head_id : kwid, repo, NULL, NULL);
	if (err)
		goto done;

	while (n <= kwm.n) {
		err = got_commit_graph_iter_next(&iter_id, graph, repo,
		    NULL, NULL);
		if (err) {
			if (err->code == GOT_ERR_ITER_COMPLETED)
				err = NULL;
			break;
		}

		if (kwm.sym == GOT_KEYWORD_DESCENDANT) {
			/*
			 * We want the Nth generation descendant of KEYWORD,
			 * so queue all commits from HEAD to KEYWORD then we
			 * can walk from KEYWORD to its Nth gen descendent.
			 */
			err = got_object_qid_alloc(&qid, &iter_id);
			if (err)
				goto done;
			STAILQ_INSERT_HEAD(&commits, qid, entry);

			if (got_object_id_cmp(&iter_id, kwid) == 0)
				break;
			continue;
		}
		++n;
	}

	if (kwm.sym == GOT_KEYWORD_DESCENDANT) {
		n = 0;

		STAILQ_FOREACH(qid, &commits, entry) {
			if (qid == STAILQ_LAST(&commits, got_object_qid, entry)
			    || n == kwm.n)
				break;
			++n;
		}

		memcpy(&iter_id, &qid->id, sizeof(iter_id));
	}

	free(kwid_str);
	err = got_object_id_str(&kwid_str, &iter_id);

done:
	free(kwid);
	free(kwm.kw);
	free(head_id);
	got_ref_list_free(&refs);
	got_object_id_queue_free(&commits);
	if (graph != NULL)
		got_commit_graph_close(graph);

	if (err != NULL) {
		free(kwid_str);
		return err;
	}

	*ret = kwid_str;
	return NULL;
}
