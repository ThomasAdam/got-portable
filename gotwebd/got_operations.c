/*
 * Copyright (c) 2020-2022 Tracey Emery <tracey@traceyemery.net>
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
#include <sys/socket.h>
#include <sys/stat.h>

#include <event.h>
#include <imsg.h>
#include <sha1.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "got_error.h"
#include "got_object.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_path.h"
#include "got_cancel.h"
#include "got_diff.h"
#include "got_commit_graph.h"
#include "got_blame.h"
#include "got_privsep.h"

#include "proc.h"
#include "gotwebd.h"

static const struct got_error *got_init_repo_commit(struct repo_commit **);
static const struct got_error *got_init_repo_tag(struct repo_tag **);
static const struct got_error *got_get_repo_commit(struct request *,
    struct repo_commit *, struct got_commit_object *, struct got_reflist_head *,
    struct got_object_id *);
static const struct got_error *got_gotweb_dupfd(int *, int *);
static const struct got_error *got_gotweb_openfile(FILE **, int *, int *);
static const struct got_error *got_gotweb_blame_cb(void *, int, int,
    struct got_commit_object *,struct got_object_id *);

const struct got_error *
got_gotweb_flushfile(FILE *f, int fd)
{
	if (fseek(f, 0, SEEK_SET) == -1)
		return got_error_from_errno("fseek");

	if (ftruncate(fd, 0) == -1)
		return got_error_from_errno("ftruncate");

	if (fsync(fd) == -1)
		return got_error_from_errno("fsync");

	if (f && fclose(f) == EOF)
		return got_error_from_errno("fclose");

	if (fd != -1 && close(fd) != -1)
		return got_error_from_errno("close");

	return NULL;
}

static const struct got_error *
got_gotweb_openfile(FILE **f, int *priv_fd, int *fd)
{
	*fd = dup(*priv_fd);
	if (*fd == -1)
		return got_error_from_errno("dup");

	*f = fdopen(*fd, "w+");
	if (*f == NULL) {
		close(*fd);
		return got_error(GOT_ERR_PRIVSEP_NO_FD);
	}

	return NULL;
}

static const struct got_error *
got_gotweb_dupfd(int *priv_fd, int *fd)
{
	*fd = dup(*priv_fd);

	if (*fd < 0)
		return NULL;

	return NULL;
}

const struct got_error *
got_get_repo_owner(char **owner, struct request *c)
{
	struct server *srv = c->srv;
	struct transport *t = c->t;
	struct got_repository *repo = t->repo;
	const char *gitconfig_owner;

	*owner = NULL;

	if (srv->show_repo_owner == 0)
		return NULL;

	gitconfig_owner = got_repo_get_gitconfig_owner(repo);
	if (gitconfig_owner) {
		*owner = strdup(gitconfig_owner);
		if (*owner == NULL)
			return got_error_from_errno("strdup");
	} else {
		*owner = strdup("");
		if (*owner == NULL)
			return got_error_from_errno("strdup");
	}
	return NULL;
}

const struct got_error *
got_get_repo_age(char **repo_age, struct request *c,
    const char *refname, int ref_tm)
{
	const struct got_error *error = NULL;
	struct server *srv = c->srv;
	struct transport *t = c->t;
	struct got_repository *repo = t->repo;
	struct got_commit_object *commit = NULL;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;
	time_t committer_time = 0, cmp_time = 0;

	*repo_age = NULL;
	TAILQ_INIT(&refs);

	if (srv->show_repo_age == 0)
		return NULL;

	error = got_ref_list(&refs, repo, "refs/heads",
	    got_ref_cmp_by_name, NULL);
	if (error)
		goto done;

	/*
	 * Find the youngest branch tip in the repository, or the age of
	 * the a specific branch tip if a name was provided by the caller.
	 */
	TAILQ_FOREACH(re, &refs, entry) {
		struct got_object_id *id = NULL;

		if (refname && strcmp(got_ref_get_name(re->ref), refname) != 0)
			continue;

		error = got_ref_resolve(&id, repo, re->ref);
		if (error)
			goto done;

		error = got_object_open_as_commit(&commit, repo, id);
		free(id);
		if (error)
			goto done;

		committer_time =
		    got_object_commit_get_committer_time(commit);
		got_object_commit_close(commit);
		if (cmp_time < committer_time)
			cmp_time = committer_time;

		if (refname)
			break;
	}

	if (cmp_time != 0) {
		committer_time = cmp_time;
		error = gotweb_get_time_str(repo_age, committer_time, ref_tm);
	}
done:
	got_ref_list_free(&refs);
	return error;
}

static const struct got_error *
got_get_repo_commit(struct request *c, struct repo_commit *repo_commit,
    struct got_commit_object *commit, struct got_reflist_head *refs,
    struct got_object_id *id)
{
	const struct got_error *error = NULL;
	struct got_reflist_entry *re;
	struct got_object_id *id2 = NULL;
	struct got_object_qid *parent_id;
	struct transport *t = c->t;
	struct querystring *qs = c->t->qs;
	char *commit_msg = NULL, *commit_msg0;

	TAILQ_FOREACH(re, refs, entry) {
		char *s;
		const char *name;
		struct got_tag_object *tag = NULL;
		struct got_object_id *ref_id;
		int cmp;

		if (got_ref_is_symbolic(re->ref))
			continue;

		name = got_ref_get_name(re->ref);
		if (strncmp(name, "refs/", 5) == 0)
			name += 5;
		if (strncmp(name, "got/", 4) == 0)
			continue;
		if (strncmp(name, "heads/", 6) == 0)
			name += 6;
		if (strncmp(name, "remotes/", 8) == 0) {
			name += 8;
			if (strstr(name, "/" GOT_REF_HEAD) != NULL)
				continue;
		}
		error = got_ref_resolve(&ref_id, t->repo, re->ref);
		if (error)
			return error;
		if (strncmp(name, "tags/", 5) == 0) {
			error = got_object_open_as_tag(&tag, t->repo, ref_id);
			if (error) {
				if (error->code != GOT_ERR_OBJ_TYPE) {
					free(ref_id);
					continue;
				}
				/*
				 * Ref points at something other
				 * than a tag.
				 */
				error = NULL;
				tag = NULL;
			}
		}
		cmp = got_object_id_cmp(tag ?
		    got_object_tag_get_object_id(tag) : ref_id, id);
		free(ref_id);
		if (tag)
			got_object_tag_close(tag);
		if (cmp != 0)
			continue;
		s = repo_commit->refs_str;
		if (asprintf(&repo_commit->refs_str, "%s%s%s", s ? s : "",
		    s ? ", " : "", name) == -1) {
			error = got_error_from_errno("asprintf");
			free(s);
			repo_commit->refs_str = NULL;
			return error;
		}
		free(s);
	}

	error = got_object_id_str(&repo_commit->commit_id, id);
	if (error)
		return error;

	error = got_object_id_str(&repo_commit->tree_id,
	    got_object_commit_get_tree_id(commit));
	if (error)
		return error;

	if (qs->action == DIFF) {
		parent_id = STAILQ_FIRST(
		    got_object_commit_get_parent_ids(commit));
		if (parent_id != NULL) {
			id2 = got_object_id_dup(&parent_id->id);
			error = got_object_id_str(&repo_commit->parent_id, id2);
			if (error)
				return error;
			free(id2);
		} else {
			repo_commit->parent_id = strdup("/dev/null");
			if (repo_commit->parent_id == NULL) {
				error = got_error_from_errno("strdup");
				return error;
			}
		}
	}

	repo_commit->committer_time =
	    got_object_commit_get_committer_time(commit);

	repo_commit->author =
	    strdup(got_object_commit_get_author(commit));
	if (repo_commit->author == NULL) {
		error = got_error_from_errno("strdup");
		return error;
	}
	repo_commit->committer =
	    strdup(got_object_commit_get_committer(commit));
	if (repo_commit->committer == NULL) {
		error = got_error_from_errno("strdup");
		return error;
	}
	error = got_object_commit_get_logmsg(&commit_msg0, commit);
	if (error)
		return error;

	commit_msg = commit_msg0;
	while (*commit_msg == '\n')
		commit_msg++;

	repo_commit->commit_msg = strdup(commit_msg);
	if (repo_commit->commit_msg == NULL)
		error = got_error_from_errno("strdup");
	free(commit_msg0);
	return error;
}

const struct got_error *
got_get_repo_commits(struct request *c, int limit)
{
	const struct got_error *error = NULL;
	struct got_object_id *id = NULL;
	struct got_commit_graph *graph = NULL;
	struct got_commit_object *commit = NULL;
	struct got_reflist_head refs;
	struct got_reference *ref = NULL;
	struct repo_commit *repo_commit = NULL;
	struct server *srv = c->srv;
	struct transport *t = c->t;
	struct got_repository *repo = t->repo;
	struct querystring *qs = t->qs;
	struct repo_dir *repo_dir = t->repo_dir;
	char *in_repo_path = NULL, *repo_path = NULL, *file_path = NULL;
	int chk_next = 0, chk_multi = 0, commit_found = 0;
	int obj_type, limit_chk = 0;

	TAILQ_INIT(&refs);

	if (qs->file != NULL && strlen(qs->file) > 0)
		if (asprintf(&file_path, "%s/%s", qs->folder ? qs->folder : "",
		    qs->file) == -1)
			return got_error_from_errno("asprintf");

	if (asprintf(&repo_path, "%s/%s", srv->repos_path,
	    repo_dir->name) == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}

	/*
	 * XXX: jumping directly to a commit id via
	 * got_repo_match_object_id_prefix significantly improves performance,
	 * but does not allow us to create a PREVIOUS button, since commits can
	 * only be itereated forward. So, we have to match as we iterate from
	 * the headref.
	 */
	if (qs->action == BRIEFS || qs->action == COMMITS ||
	    (qs->action == TREE && qs->commit == NULL)) {
		error = got_ref_open(&ref, repo, qs->headref, 0);
		if (error)
			goto done;

		error = got_ref_resolve(&id, repo, ref);
		if (error)
			goto done;
	} else if (qs->commit != NULL) {
		error = got_ref_open(&ref, repo, qs->commit, 0);
		if (error == NULL) {
			error = got_ref_resolve(&id, repo, ref);
			if (error)
				goto done;
			error = got_object_get_type(&obj_type, repo, id);
			if (error)
				goto done;
			if (obj_type == GOT_OBJ_TYPE_TAG) {
				struct got_tag_object *tag;
				error = got_object_open_as_tag(&tag, repo, id);
				if (error)
					goto done;
				if (got_object_tag_get_object_type(tag) !=
				    GOT_OBJ_TYPE_COMMIT) {
					got_object_tag_close(tag);
					error = got_error(GOT_ERR_OBJ_TYPE);
					goto done;
				}
				free(id);
				id = got_object_id_dup(
				    got_object_tag_get_object_id(tag));
				if (id == NULL)
					error = got_error_from_errno(
					    "got_object_id_dup");
				got_object_tag_close(tag);
				if (error)
					goto done;
			} else if (obj_type != GOT_OBJ_TYPE_COMMIT) {
				error = got_error(GOT_ERR_OBJ_TYPE);
				goto done;
			}
		}
		error = got_repo_match_object_id_prefix(&id, qs->commit,
		    GOT_OBJ_TYPE_COMMIT, repo);
		if (error)
			goto done;
	}

	error = got_repo_map_path(&in_repo_path, repo, repo_path);
	if (error)
		goto done;

	error = got_ref_list(&refs, repo, NULL, got_ref_cmp_by_name, NULL);
	if (error)
		goto done;

	if (qs->file != NULL && strlen(qs->file) > 0) {
		error = got_commit_graph_open(&graph, file_path, 0);
		if (error)
			goto done;
	} else {
		error = got_commit_graph_open(&graph, in_repo_path, 0);
		if (error)
			goto done;
	}

	error = got_commit_graph_iter_start(graph, id, repo, NULL, NULL);
	if (error)
		goto done;

	for (;;) {
		struct got_object_id next_id;

		error = got_commit_graph_iter_next(&next_id, graph, repo, NULL,
		    NULL);
		if (error) {
			if (error->code == GOT_ERR_ITER_COMPLETED)
				error = NULL;
			goto done;
		}

		error = got_object_open_as_commit(&commit, repo, &next_id);
		if (error)
			goto done;

		error = got_ref_list(&refs, repo, NULL, got_ref_cmp_by_name,
		    NULL);
		if (error)
			goto done;

		error = got_init_repo_commit(&repo_commit);
		if (error)
			goto done;

		error = got_get_repo_commit(c, repo_commit, commit,
		    &refs, &next_id);
		if (error) {
			gotweb_free_repo_commit(repo_commit);
			goto done;
		}

		if (limit_chk == ((limit * qs->page) - limit) &&
		    commit_found == 0 && repo_commit->commit_id != NULL) {
			t->prev_id = strdup(repo_commit->commit_id);
			if (t->prev_id == NULL) {
				error = got_error_from_errno("strdup");
				gotweb_free_repo_commit(repo_commit);
				goto done;
			}
		}

		if (qs->commit != NULL && commit_found == 0 && limit != 1) {
			if (strcmp(qs->commit, repo_commit->commit_id) == 0)
				commit_found = 1;
			else if (qs->file != NULL && strlen(qs->file) > 0 &&
			    qs->page == 0)
				commit_found = 1;
			else {
				gotweb_free_repo_commit(repo_commit);
				limit_chk++;
				continue;
			}
		}

		TAILQ_INSERT_TAIL(&t->repo_commits, repo_commit, entry);

		if (limit == 1 && chk_multi == 0 &&
		    srv->max_commits_display != 1)
			commit_found = 1;
		else {
			chk_multi = 1;

			/*
			 * check for one more commit before breaking,
			 * so we know whether to navigate through briefs
			 * commits and summary
			 */
			if (chk_next && (qs->action == BRIEFS ||
			    qs->action == COMMITS || qs->action == SUMMARY)) {
				t->next_id = strdup(repo_commit->commit_id);
				if (t->next_id == NULL) {
					error = got_error_from_errno("strdup");
					goto done;
				}
				if (commit) {
					got_object_commit_close(commit);
					commit = NULL;
				}
				TAILQ_REMOVE(&t->repo_commits, repo_commit,
				    entry);
				gotweb_free_repo_commit(repo_commit);
				goto done;
			}
		}
		got_ref_list_free(&refs);
		if (error || (limit && --limit == 0)) {
			if (commit_found || (qs->file != NULL &&
			    strlen(qs->file) > 0))
				if (chk_multi == 0)
					break;
			chk_next = 1;
		}
		if (commit) {
			got_object_commit_close(commit);
			commit = NULL;
		}
	}
done:
	if (ref)
		got_ref_close(ref);
	if (commit)
		got_object_commit_close(commit);
	if (graph)
		got_commit_graph_close(graph);
	got_ref_list_free(&refs);
	free(in_repo_path);
	free(file_path);
	free(repo_path);
	free(id);
	return error;
}

const struct got_error *
got_get_repo_tags(struct request *c, int limit)
{
	const struct got_error *error = NULL;
	struct got_object_id *id = NULL;
	struct got_commit_object *commit = NULL;
	struct got_reflist_head refs;
	struct got_reference *ref;
	struct got_reflist_entry *re;
	struct server *srv = c->srv;
	struct transport *t = c->t;
	struct got_repository *repo = t->repo;
	struct querystring *qs = t->qs;
	struct repo_dir *repo_dir = t->repo_dir;
	struct got_tag_object *tag = NULL;
	struct repo_tag *rt = NULL, *trt = NULL;
	char *in_repo_path = NULL, *repo_path = NULL, *id_str = NULL;
	char *tag_commit = NULL, *tag_commit0 = NULL;
	char *commit_msg = NULL, *commit_msg0 = NULL;
	int chk_next = 0, chk_multi = 1, commit_found = 0, c_cnt = 0;

	TAILQ_INIT(&refs);

	if (asprintf(&repo_path, "%s/%s", srv->repos_path,
	    repo_dir->name) == -1)
		return got_error_from_errno("asprintf");

	if (qs->commit == NULL && (qs->action == TAGS || qs->action == RSS)) {
		error = got_ref_open(&ref, repo, qs->headref, 0);
		if (error)
			goto err;
		error = got_ref_resolve(&id, repo, ref);
		got_ref_close(ref);
		if (error)
			goto err;
	} else if (qs->commit == NULL && qs->action == TAG) {
		error = got_error_msg(GOT_ERR_EOF, "commit id missing");
		goto err;
	} else {
		error = got_repo_match_object_id_prefix(&id, qs->commit,
		    GOT_OBJ_TYPE_COMMIT, repo);
		if (error)
			goto err;
	}

	if (qs->action != SUMMARY && qs->action != TAGS) {
		error = got_object_open_as_commit(&commit, repo, id);
		if (error)
			goto err;
		error = got_object_commit_get_logmsg(&commit_msg0, commit);
		if (error)
			goto err;
		if (commit) {
			got_object_commit_close(commit);
			commit = NULL;
		}
	}

	error = got_repo_map_path(&in_repo_path, repo, repo_path);
	if (error)
		goto err;

	error = got_ref_list(&refs, repo, "refs/tags", got_ref_cmp_tags,
	   repo);
	if (error)
		goto err;

	if (limit == 1)
		chk_multi = 0;

	/*
	 * XXX: again, see previous message about caching
	 */

	TAILQ_FOREACH(re, &refs, entry) {
		struct repo_tag *new_repo_tag = NULL;
		error = got_init_repo_tag(&new_repo_tag);
		if (error)
			goto err;

		TAILQ_INSERT_TAIL(&t->repo_tags, new_repo_tag, entry);

		new_repo_tag->tag_name = strdup(got_ref_get_name(re->ref));
		if (new_repo_tag->tag_name == NULL) {
			error = got_error_from_errno("strdup");
			goto err;
		}

		free(id);
		id = NULL;

		free(id_str);
		id_str = NULL;

		error = got_ref_resolve(&id, repo, re->ref);
		if (error)
			goto done;

		if (tag)
			got_object_tag_close(tag);
		error = got_object_open_as_tag(&tag, repo, id);
		if (error) {
			if (error->code != GOT_ERR_OBJ_TYPE)
				goto done;
			/* "lightweight" tag */
			error = got_object_open_as_commit(&commit, repo, id);
			if (error)
				goto done;
			new_repo_tag->tagger =
			    strdup(got_object_commit_get_committer(commit));
			if (new_repo_tag->tagger == NULL) {
				error = got_error_from_errno("strdup");
				goto err;
			}
			new_repo_tag->tagger_time =
			    got_object_commit_get_committer_time(commit);
			error = got_object_id_str(&id_str, id);
			if (error)
				goto err;
		} else {
			new_repo_tag->tagger =
			    strdup(got_object_tag_get_tagger(tag));
			if (new_repo_tag->tagger == NULL) {
				error = got_error_from_errno("strdup");
				goto err;
			}
			new_repo_tag->tagger_time =
			    got_object_tag_get_tagger_time(tag);
			error = got_object_id_str(&id_str,
			    got_object_tag_get_object_id(tag));
			if (error)
				goto err;
		}

		new_repo_tag->commit_id = strdup(id_str);
		if (new_repo_tag->commit_id == NULL)
			goto err;

		if (commit_found == 0 && qs->commit != NULL &&
		    strncmp(id_str, qs->commit, strlen(id_str)) != 0)
			continue;
		else
			commit_found = 1;

		t->tag_count++;

		/*
		 * check for one more commit before breaking,
		 * so we know whether to navigate through briefs
		 * commits and summary
		 */
		if (chk_next) {
			t->next_id = strdup(new_repo_tag->commit_id);
			if (t->next_id == NULL) {
				error = got_error_from_errno("strdup");
				goto err;
			}
			if (commit) {
				got_object_commit_close(commit);
				commit = NULL;
			}
			TAILQ_REMOVE(&t->repo_tags, new_repo_tag, entry);
			gotweb_free_repo_tag(new_repo_tag);
			goto done;
		}

		if (commit) {
			error = got_object_commit_get_logmsg(&tag_commit0,
			    commit);
			if (error)
				goto err;
			got_object_commit_close(commit);
			commit = NULL;
		} else {
			tag_commit0 = strdup(got_object_tag_get_message(tag));
			if (tag_commit0 == NULL) {
				error = got_error_from_errno("strdup");
				goto err;
			}
		}

		tag_commit = tag_commit0;
		while (*tag_commit == '\n')
			tag_commit++;
		new_repo_tag->tag_commit = strdup(tag_commit);
		if (new_repo_tag->tag_commit == NULL) {
			error = got_error_from_errno("strdup");
			free(tag_commit0);
			goto err;
		}
		free(tag_commit0);

		if (qs->action != SUMMARY && qs->action != TAGS) {
			commit_msg = commit_msg0;
			while (*commit_msg == '\n')
				commit_msg++;

			new_repo_tag->commit_msg = strdup(commit_msg);
			if (new_repo_tag->commit_msg == NULL) {
				error = got_error_from_errno("strdup");
				goto err;
			}
		}

		if (limit && --limit == 0) {
			if (chk_multi == 0)
				break;
			chk_next = 1;
		}
	}

done:
	/*
	 * we have tailq populated, so find previous commit id
	 * for navigation through briefs and commits
	 */
	if (t->tag_count == 0) {
		TAILQ_FOREACH_SAFE(rt, &t->repo_tags, entry, trt) {
			TAILQ_REMOVE(&t->repo_tags, rt, entry);
			gotweb_free_repo_tag(rt);
		}
	}
	if (t->tag_count > 0 && t->prev_id == NULL && qs->commit != NULL) {
		commit_found = 0;
		TAILQ_FOREACH_REVERSE(rt, &t->repo_tags, repo_tags_head,
		    entry) {
			if (commit_found == 0 && rt->commit_id != NULL &&
			    strcmp(qs->commit, rt->commit_id) != 0) {
				continue;
			} else
				commit_found = 1;
			if (c_cnt == srv->max_commits_display ||
			    rt == TAILQ_FIRST(&t->repo_tags)) {
				t->prev_id = strdup(rt->commit_id);
				if (t->prev_id == NULL)
					error = got_error_from_errno("strdup");
				break;
			}
			c_cnt++;
		}
	}
err:
	if (commit)
		got_object_commit_close(commit);
	if (tag)
		got_object_tag_close(tag);
	got_ref_list_free(&refs);
	free(commit_msg0);
	free(in_repo_path);
	free(repo_path);
	free(id);
	free(id_str);
	return error;
}

int
got_output_repo_tree(struct request *c,
    int (*cb)(struct template *, struct got_tree_entry *))
{
	const struct got_error *error = NULL;
	struct transport *t = c->t;
	struct got_commit_object *commit = NULL;
	struct got_repository *repo = t->repo;
	struct querystring *qs = t->qs;
	struct repo_commit *rc = NULL;
	struct got_object_id *tree_id = NULL, *commit_id = NULL;
	struct got_reflist_head refs;
	struct got_tree_object *tree = NULL;
	struct got_tree_entry *te;
	struct repo_dir *repo_dir = t->repo_dir;
	char *escaped_name = NULL, *path = NULL;
	int nentries, i;

	TAILQ_INIT(&refs);

	rc = TAILQ_FIRST(&t->repo_commits);

	if (qs->folder != NULL) {
		path = strdup(qs->folder);
		if (path == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
	} else {
		error = got_repo_map_path(&path, repo, repo_dir->path);
		if (error)
			goto done;
	}

	error = got_repo_match_object_id(&commit_id, NULL, rc->commit_id,
	    GOT_OBJ_TYPE_COMMIT, &refs, repo);
	if (error)
		goto done;

	error = got_object_open_as_commit(&commit, repo, commit_id);
	if (error)
		goto done;

	error = got_object_id_by_path(&tree_id, repo, commit, path);
	if (error)
		goto done;

	error = got_object_open_as_tree(&tree, repo, tree_id);
	if (error)
		goto done;

	nentries = got_object_tree_get_nentries(tree);

	for (i = 0; i < nentries; i++) {
		te = got_object_tree_get_entry(tree, i);
		if (cb(c->tp, te) == -1)
			break;
	}
done:
	free(escaped_name);
	free(path);
	got_ref_list_free(&refs);
	if (commit)
		got_object_commit_close(commit);
	if (tree)
		got_object_tree_close(tree);
	free(commit_id);
	free(tree_id);
	if (error) {
		log_warnx("%s: %s", __func__, error->msg);
		return -1;
	}
	return 0;
}

const struct got_error *
got_open_blob_for_output(struct got_blob_object **blob, int *fd,
    int *binary, struct request *c)
{
	const struct got_error *error = NULL;
	struct transport *t = c->t;
	struct got_repository *repo = t->repo;
	struct querystring *qs = c->t->qs;
	struct got_commit_object *commit = NULL;
	struct got_object_id *commit_id = NULL;
	struct got_reflist_head refs;
	char *path = NULL, *in_repo_path = NULL;
	int obj_type;

	TAILQ_INIT(&refs);

	*blob = NULL;
	*fd = -1;
	*binary = 0;

	if (asprintf(&path, "%s%s%s", qs->folder ? qs->folder : "",
	    qs->folder ? "/" : "", qs->file) == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}

	error = got_repo_map_path(&in_repo_path, repo, path);
	if (error)
		goto done;

	error = got_repo_match_object_id(&commit_id, NULL, qs->commit,
	    GOT_OBJ_TYPE_COMMIT, &refs, repo);
	if (error)
		goto done;

	error = got_object_open_as_commit(&commit, repo, commit_id);
	if (error)
		goto done;

	error = got_object_id_by_path(&commit_id, repo, commit, in_repo_path);
	if (error)
		goto done;

	if (commit_id == NULL) {
		error = got_error(GOT_ERR_NO_OBJ);
		goto done;
	}

	error = got_object_get_type(&obj_type, repo, commit_id);
	if (error)
		goto done;

	if (obj_type != GOT_OBJ_TYPE_BLOB) {
		error = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	error = got_gotweb_dupfd(&c->priv_fd[BLOB_FD_1], fd);
	if (error)
		goto done;

	error = got_object_open_as_blob(blob, repo, commit_id, BUF, *fd);
	if (error)
		goto done;

	error = got_object_blob_is_binary(binary, *blob);
	if (error)
		goto done;

 done:
	if (commit)
		got_object_commit_close(commit);

	if (error) {
		if (*fd != -1)
			close(*fd);
		if (*blob)
			got_object_blob_close(*blob);
		*fd = -1;
		*blob = NULL;
	}

	free(in_repo_path);
	free(commit_id);
	free(path);
	return error;
}

int
got_output_blob_by_lines(struct template *tp, struct got_blob_object *blob,
    int (*cb)(struct template *, const char *, size_t))
{
	const struct got_error	*err;
	char			*line = NULL;
	size_t			 linesize = 0;
	size_t			 lineno = 0;
	ssize_t			 linelen = 0;

	for (;;) {
		err = got_object_blob_getline(&line, &linelen, &linesize,
		    blob);
		if (err || linelen == -1)
			break;
		lineno++;
		if (cb(tp, line, lineno) == -1)
			break;
	}

	free(line);

	if (err) {
		log_warnx("%s: got_object_blob_getline failed: %s",
		    __func__, err->msg);
		return -1;
	}
	return 0;
}

struct blame_cb_args {
	struct blame_line *lines;
	int nlines;
	int nlines_prec;
	int lineno_cur;
	off_t *line_offsets;
	FILE *f;
	struct got_repository *repo;
	struct request *c;
	got_render_blame_line_cb cb;
};

static const struct got_error *
got_gotweb_blame_cb(void *arg, int nlines, int lineno,
    struct got_commit_object *commit, struct got_object_id *id)
{
	const struct got_error *err = NULL;
	struct blame_cb_args *a = arg;
	struct blame_line *bline;
	struct request *c = a->c;
	char *line = NULL;
	size_t linesize = 0;
	off_t offset;
	struct tm tm;
	time_t committer_time;

	if (nlines != a->nlines ||
	    (lineno != -1 && lineno < 1) || lineno > a->nlines)
		return got_error(GOT_ERR_RANGE);

	if (lineno == -1)
		return NULL; /* no change in this commit */

	/* Annotate this line. */
	bline = &a->lines[lineno - 1];
	if (bline->annotated)
		return NULL;
	err = got_object_id_str(&bline->id_str, id);
	if (err)
		return err;

	bline->committer = strdup(got_object_commit_get_committer(commit));
	if (bline->committer == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

	committer_time = got_object_commit_get_committer_time(commit);
	if (gmtime_r(&committer_time, &tm) == NULL)
		return got_error_from_errno("gmtime_r");
	if (strftime(bline->datebuf, sizeof(bline->datebuf), "%G-%m-%d",
	    &tm) == 0) {
		err = got_error(GOT_ERR_NO_SPACE);
		goto done;
	}
	bline->annotated = 1;

	/* Print lines annotated so far. */
	bline = &a->lines[a->lineno_cur - 1];
	if (!bline->annotated)
		goto done;

	offset = a->line_offsets[a->lineno_cur - 1];
	if (fseeko(a->f, offset, SEEK_SET) == -1) {
		err = got_error_from_errno("fseeko");
		goto done;
	}

	while (a->lineno_cur <= a->nlines && bline->annotated) {
		if (getline(&line, &linesize, a->f) == -1) {
			if (ferror(a->f))
				err = got_error_from_errno("getline");
			break;
		}

		if (a->cb(c->tp, line, bline, a->nlines_prec,
		    a->lineno_cur) == -1)
			break;

		a->lineno_cur++;
		bline = &a->lines[a->lineno_cur - 1];
	}
done:
	free(line);
	return err;
}

const struct got_error *
got_output_file_blame(struct request *c, got_render_blame_line_cb cb)
{
	const struct got_error *error = NULL;
	struct transport *t = c->t;
	struct got_repository *repo = t->repo;
	struct querystring *qs = c->t->qs;
	struct got_object_id *obj_id = NULL, *commit_id = NULL;
	struct got_commit_object *commit = NULL;
	struct got_reflist_head refs;
	struct got_blob_object *blob = NULL;
	char *path = NULL, *in_repo_path = NULL;
	struct blame_cb_args bca;
	int i, obj_type, fd1 = -1, fd2 = -1, fd3 = -1, fd4 = -1, fd5 = -1;
	int fd6 = -1;
	off_t filesize;
	FILE *f1 = NULL, *f2 = NULL;

	TAILQ_INIT(&refs);
	bca.f = NULL;
	bca.lines = NULL;
	bca.cb = cb;

	if (asprintf(&path, "%s%s%s", qs->folder ? qs->folder : "",
	    qs->folder ? "/" : "", qs->file) == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}

	error = got_repo_map_path(&in_repo_path, repo, path);
	if (error)
		goto done;

	error = got_repo_match_object_id(&commit_id, NULL, qs->commit,
	    GOT_OBJ_TYPE_COMMIT, &refs, repo);
	if (error)
		goto done;

	error = got_object_open_as_commit(&commit, repo, commit_id);
	if (error)
		goto done;

	error = got_object_id_by_path(&obj_id, repo, commit, in_repo_path);
	if (error)
		goto done;

	error = got_object_get_type(&obj_type, repo, obj_id);
	if (error)
		goto done;

	if (obj_type != GOT_OBJ_TYPE_BLOB) {
		error = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	error = got_gotweb_openfile(&bca.f, &c->priv_fd[BLAME_FD_1], &fd1);
	if (error)
		goto done;

	error = got_gotweb_dupfd(&c->priv_fd[BLAME_FD_2], &fd2);
	if (error)
		goto done;

	error = got_object_open_as_blob(&blob, repo, obj_id, BUF, fd2);
	if (error)
		goto done;

	error = got_object_blob_dump_to_file(&filesize, &bca.nlines,
	    &bca.line_offsets, bca.f, blob);
	if (error || bca.nlines == 0)
		goto done;

	/* Don't include \n at EOF in the blame line count. */
	if (bca.line_offsets[bca.nlines - 1] == filesize)
		bca.nlines--;

	bca.lines = calloc(bca.nlines, sizeof(*bca.lines));
	if (bca.lines == NULL) {
		error = got_error_from_errno("calloc");
		goto done;
	}
	bca.lineno_cur = 1;
	bca.nlines_prec = 0;
	i = bca.nlines;
	while (i > 0) {
		i /= 10;
		bca.nlines_prec++;
	}
	bca.repo = repo;
	bca.c = c;

	error = got_gotweb_dupfd(&c->priv_fd[BLAME_FD_3], &fd3);
	if (error)
		goto done;

	error = got_gotweb_dupfd(&c->priv_fd[BLAME_FD_4], &fd4);
	if (error)
		goto done;

	error = got_gotweb_openfile(&f1, &c->priv_fd[BLAME_FD_5], &fd5);
	if (error)
		goto done;

	error = got_gotweb_openfile(&f2, &c->priv_fd[BLAME_FD_6], &fd6);
	if (error)
		goto done;

	error = got_blame(in_repo_path, commit_id, repo,
	    GOT_DIFF_ALGORITHM_MYERS, got_gotweb_blame_cb, &bca, NULL, NULL,
	    fd3, fd4, f1, f2);

done:
	if (bca.lines) {
		free(bca.line_offsets);
		for (i = 0; i < bca.nlines; i++) {
			struct blame_line *bline = &bca.lines[i];
			free(bline->id_str);
			free(bline->committer);
		}
	}
	free(bca.lines);
	if (fd2 != -1 && close(fd2) == -1 && error == NULL)
		error = got_error_from_errno("close");
	if (fd3 != -1 && close(fd3) == -1 && error == NULL)
		error = got_error_from_errno("close");
	if (fd4 != -1 && close(fd4) == -1 && error == NULL)
		error = got_error_from_errno("close");
	if (bca.f) {
		const struct got_error *bca_err =
		    got_gotweb_flushfile(bca.f, fd1);
		if (error == NULL)
			error = bca_err;
	}
	if (f1) {
		const struct got_error *f1_err =
		    got_gotweb_flushfile(f1, fd5);
		if (error == NULL)
			error = f1_err;
	}
	if (f2) {
		const struct got_error *f2_err =
		    got_gotweb_flushfile(f2, fd6);
		if (error == NULL)
			error = f2_err;
	}
	if (commit)
		got_object_commit_close(commit);
	if (blob)
		got_object_blob_close(blob);
	free(in_repo_path);
	free(commit_id);
	free(obj_id);
	free(path);
	got_ref_list_free(&refs);
	return error;
}

const struct got_error *
got_open_diff_for_output(FILE **fp, int *fd, struct request *c)
{
	const struct got_error *error = NULL;
	struct transport *t = c->t;
	struct got_repository *repo = t->repo;
	struct repo_commit *rc = NULL;
	struct got_object_id *id1 = NULL, *id2 = NULL;
	struct got_reflist_head refs;
	FILE *f1 = NULL, *f2 = NULL, *f3 = NULL;
	int obj_type, fd1, fd2, fd3, fd4 = -1, fd5 = -1;

	*fp = NULL;
	*fd = -1;

	TAILQ_INIT(&refs);

	error = got_gotweb_openfile(&f1, &c->priv_fd[DIFF_FD_1], &fd1);
	if (error)
		return error;

	error = got_gotweb_openfile(&f2, &c->priv_fd[DIFF_FD_2], &fd2);
	if (error)
		return error;

	error = got_gotweb_openfile(&f3, &c->priv_fd[DIFF_FD_3], &fd3);
	if (error)
		return error;

	rc = TAILQ_FIRST(&t->repo_commits);

	if (rc->parent_id != NULL &&
	    strncmp(rc->parent_id, "/dev/null", 9) != 0) {
		error = got_repo_match_object_id(&id1, NULL,
		    rc->parent_id, GOT_OBJ_TYPE_ANY,
		    &refs, repo);
		if (error)
			goto done;
	}

	error = got_repo_match_object_id(&id2, NULL, rc->commit_id,
	    GOT_OBJ_TYPE_ANY, &refs, repo);
	if (error)
		goto done;

	error = got_object_get_type(&obj_type, repo, id2);
	if (error)
		goto done;

	error = got_gotweb_dupfd(&c->priv_fd[DIFF_FD_4], &fd4);
	if (error)
		goto done;

	error = got_gotweb_dupfd(&c->priv_fd[DIFF_FD_5], &fd5);
	if (error)
		goto done;

	switch (obj_type) {
	case GOT_OBJ_TYPE_BLOB:
		error = got_diff_objects_as_blobs(NULL, NULL, f1, f2, fd4, fd5,
		     id1, id2, NULL, NULL, GOT_DIFF_ALGORITHM_MYERS, 3, 0, 0,
		     NULL, repo, f3);
		break;
	case GOT_OBJ_TYPE_TREE:
		error = got_diff_objects_as_trees(NULL, NULL, f1, f2, fd4, fd5,
		    id1, id2, NULL, "", "",  GOT_DIFF_ALGORITHM_MYERS, 3, 0, 0,
		    NULL, repo, f3);
		break;
	case GOT_OBJ_TYPE_COMMIT:
		error = got_diff_objects_as_commits(NULL, NULL, f1, f2, fd4,
		    fd5, id1, id2, NULL,  GOT_DIFF_ALGORITHM_MYERS, 3, 0, 0,
		    NULL, repo, f3);
		break;
	default:
		error = got_error(GOT_ERR_OBJ_TYPE);
	}
	if (error)
		goto done;

	if (fseek(f1, 0, SEEK_SET) == -1) {
		error = got_ferror(f1, GOT_ERR_IO);
		goto done;
	}

	if (fseek(f2, 0, SEEK_SET) == -1) {
		error = got_ferror(f2, GOT_ERR_IO);
		goto done;
	}

	if (fseek(f3, 0, SEEK_SET) == -1) {
		error = got_ferror(f3, GOT_ERR_IO);
		goto done;
	}

	*fp = f3;
	*fd = fd3;

done:
	if (fd4 != -1 && close(fd4) == -1 && error == NULL)
		error = got_error_from_errno("close");
	if (fd5 != -1 && close(fd5) == -1 && error == NULL)
		error = got_error_from_errno("close");
	if (f1) {
		const struct got_error *f1_err =
		    got_gotweb_flushfile(f1, fd1);
		if (error == NULL)
			error = f1_err;
	}
	if (f2) {
		const struct got_error *f2_err =
		    got_gotweb_flushfile(f2, fd2);
		if (error == NULL)
			error = f2_err;
	}
	if (error && f3) {
		got_gotweb_flushfile(f3, fd3);
		*fp = NULL;
		*fd = -1;
	}
	got_ref_list_free(&refs);
	free(id1);
	free(id2);
	return error;
}

static const struct got_error *
got_init_repo_commit(struct repo_commit **rc)
{
	*rc = calloc(1, sizeof(**rc));
	if (*rc == NULL)
		return got_error_from_errno2("%s: calloc", __func__);

	(*rc)->path = NULL;
	(*rc)->refs_str = NULL;
	(*rc)->commit_id = NULL;
	(*rc)->committer = NULL;
	(*rc)->author = NULL;
	(*rc)->parent_id = NULL;
	(*rc)->tree_id = NULL;
	(*rc)->commit_msg = NULL;

	return NULL;
}

static const struct got_error *
got_init_repo_tag(struct repo_tag **rt)
{
	*rt = calloc(1, sizeof(**rt));
	if (*rt == NULL)
		return got_error_from_errno2("%s: calloc", __func__);

	(*rt)->commit_id = NULL;
	(*rt)->tag_name = NULL;
	(*rt)->tag_commit = NULL;
	(*rt)->commit_msg = NULL;
	(*rt)->tagger = NULL;

	return NULL;
}
