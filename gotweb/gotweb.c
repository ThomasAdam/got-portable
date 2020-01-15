/*
 * Copyright (c) 2019, 2020 Tracey Emery <tracey@traceyemery.net>
 * Copyright (c) 2018, 2019 Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2014, 2015, 2017 Kristaps Dzonsons <kristaps@bsd.lv>
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
#include <sys/types.h>

#include <dirent.h>
#include <err.h>
#include <regex.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <got_object.h>
#include <got_reference.h>
#include <got_repository.h>
#include <got_path.h>
#include <got_cancel.h>
#include <got_worktree.h>
#include <got_diff.h>
#include <got_commit_graph.h>
#include <got_blame.h>
#include <got_privsep.h>
#include <got_opentemp.h>

#include <kcgi.h>
#include <kcgihtml.h>

#include "buf.h"
#include "gotweb.h"
#include "gotweb_ui.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

struct trans {
	TAILQ_HEAD(dirs, gw_dir) gw_dirs;
	struct gw_dir		*gw_dir;
	struct gotweb_conf	*gw_conf;
	struct ktemplate	*gw_tmpl;
	struct khtmlreq		*gw_html_req;
	struct kreq		*gw_req;
	char			*repo_name;
	char			*repo_path;
	char			*commit;
	char			*repo_file;
	char			*action_name;
	char			*headref;
	unsigned int		 action;
	unsigned int		 page;
	unsigned int		 repos_total;
	enum kmime		 mime;
};

enum gw_key {
	KEY_PATH,
	KEY_ACTION,
	KEY_COMMIT_ID,
	KEY_FILE,
	KEY_PAGE,
	KEY_HEADREF,
	KEY__MAX
};

struct gw_dir {
	TAILQ_ENTRY(gw_dir)	 entry;
	char			*name;
	char			*owner;
	char			*description;
	char			*url;
	char			*age;
	char			*path;
};

enum tmpl {
	TEMPL_HEAD,
	TEMPL_HEADER,
	TEMPL_SITEPATH,
	TEMPL_SITEOWNER,
	TEMPL_TITLE,
	TEMPL_SEARCH,
	TEMPL_CONTENT,
	TEMPL__MAX
};

enum ref_tm {
	TM_DIFF,
	TM_LONG,
};

enum logs {
	LOGBRIEF,
	LOGCOMMIT,
	LOGFULL,
	LOGTREE,
	LOGDIFF,
	LOGBLAME,
	LOGTAG,
};

enum tags {
	TAGBRIEF,
	TAGFULL,
};

struct buf {
	u_char	*cb_buf;
	size_t	 cb_size;
	size_t	 cb_len;
};

static const char *const templs[TEMPL__MAX] = {
	"head",
	"header",
	"sitepath",
	"siteowner",
	"title",
	"search",
	"content",
};

static const struct kvalid gw_keys[KEY__MAX] = {
	{ kvalid_stringne,	"path" },
	{ kvalid_stringne,	"action" },
	{ kvalid_stringne,	"commit" },
	{ kvalid_stringne,	"file" },
	{ kvalid_int,		"page" },
	{ kvalid_stringne,	"headref" },
};

int				 gw_get_repo_log_count(struct trans *, char *);

static struct gw_dir		*gw_init_gw_dir(char *);

static char			*gw_get_repo_description(struct trans *,
				    char *);
static char			*gw_get_repo_owner(struct trans *,
				    char *);
static char			*gw_get_time_str(time_t, int);
static char			*gw_get_repo_age(struct trans *,
				    char *, char *, int);
static char			*gw_get_repo_log(struct trans *, const char *,
				    char *, int, int);
static char			*gw_get_repo_tags(struct trans *, int, int);
static char			*gw_get_repo_heads(struct trans *);
static char			*gw_get_clone_url(struct trans *, char *);
static char			*gw_get_got_link(struct trans *);
static char			*gw_get_site_link(struct trans *);
static char			*gw_html_escape(const char *);

static void			 gw_display_open(struct trans *, enum khttp,
				    enum kmime);
static void			 gw_display_index(struct trans *,
				    const struct got_error *);

static int			 gw_template(size_t, void *);

static const struct got_error*	 apply_unveil(const char *, const char *);
static const struct got_error*	 cmp_tags(void *, int *,
				    struct got_reference *,
				    struct got_reference *);
static const struct got_error*	 gw_load_got_paths(struct trans *);
static const struct got_error*	 gw_load_got_path(struct trans *,
				    struct gw_dir *);
static const struct got_error*	 gw_parse_querystring(struct trans *);
static const struct got_error*	 match_logmsg(int *, struct got_object_id *,
				    struct got_commit_object *, regex_t *);

static const struct got_error*	 gw_blame(struct trans *);
static const struct got_error*	 gw_blob(struct trans *);
static const struct got_error*	 gw_blobdiff(struct trans *);
static const struct got_error*	 gw_commit(struct trans *);
static const struct got_error*	 gw_commitdiff(struct trans *);
static const struct got_error*	 gw_history(struct trans *);
static const struct got_error*	 gw_index(struct trans *);
static const struct got_error*	 gw_log(struct trans *);
static const struct got_error*	 gw_raw(struct trans *);
static const struct got_error*	 gw_logbriefs(struct trans *);
static const struct got_error*	 gw_snapshot(struct trans *);
static const struct got_error*	 gw_summary(struct trans *);
static const struct got_error*	 gw_tag(struct trans *);
static const struct got_error*	 gw_tree(struct trans *);

struct gw_query_action {
	unsigned int		 func_id;
	const char		*func_name;
	const struct got_error	*(*func_main)(struct trans *);
	char			*template;
};

enum gw_query_actions {
	GW_BLAME,
	GW_BLOB,
	GW_BLOBDIFF,
	GW_COMMIT,
	GW_COMMITDIFF,
	GW_ERR,
	GW_HISTORY,
	GW_INDEX,
	GW_LOG,
	GW_RAW,
	GW_LOGBRIEFS,
	GW_SNAPSHOT,
	GW_SUMMARY,
	GW_TAG,
	GW_TREE,
};

static struct gw_query_action gw_query_funcs[] = {
	{ GW_BLAME,	 "blame",	gw_blame,	"gw_tmpl/index.tmpl" },
	{ GW_BLOB,	 "blob",	gw_blob,	"gw_tmpl/index.tmpl" },
	{ GW_BLOBDIFF,	 "blobdiff",	gw_blobdiff,	"gw_tmpl/index.tmpl" },
	{ GW_COMMIT,	 "commit",	gw_commit,	"gw_tmpl/index.tmpl" },
	{ GW_COMMITDIFF, "commitdiff",	gw_commitdiff,	"gw_tmpl/index.tmpl" },
	{ GW_ERR,	 NULL,		NULL,		"gw_tmpl/index.tmpl" },
	{ GW_HISTORY,	 "history",	gw_history,	"gw_tmpl/index.tmpl" },
	{ GW_INDEX,	 "index",	gw_index,	"gw_tmpl/index.tmpl" },
	{ GW_LOG,	 "log",		gw_log,		"gw_tmpl/index.tmpl" },
	{ GW_RAW,	 "raw",		gw_raw,		"gw_tmpl/index.tmpl" },
	{ GW_LOGBRIEFS,	 "logbriefs",	gw_logbriefs,	"gw_tmpl/index.tmpl" },
	{ GW_SNAPSHOT,	 "snapshot",	gw_snapshot,	"gw_tmpl/index.tmpl" },
	{ GW_SUMMARY,	 "summary",	gw_summary,	"gw_tmpl/index.tmpl" },
	{ GW_TAG,	 "tag",		gw_tag,		"gw_tmpl/index.tmpl" },
	{ GW_TREE,	 "tree",	gw_tree,	"gw_tmpl/index.tmpl" },
};

static const struct got_error *
apply_unveil(const char *repo_path, const char *repo_file)
{
	const struct got_error *err;

	if (repo_path && repo_file) {
		char *full_path;
		if ((asprintf(&full_path, "%s/%s", repo_path, repo_file)) == -1)
			return got_error_from_errno("asprintf unveil");
		if (unveil(full_path, "r") != 0)
			return got_error_from_errno2("unveil", full_path);
	}

	if (repo_path && unveil(repo_path, "r") != 0)
		return got_error_from_errno2("unveil", repo_path);

	if (unveil("/tmp", "rwc") != 0)
		return got_error_from_errno2("unveil", "/tmp");

	err = got_privsep_unveil_exec_helpers();
	if (err != NULL)
		return err;

	if (unveil(NULL, NULL) != 0)
		return got_error_from_errno("unveil");

	return NULL;
}

static const struct got_error *
cmp_tags(void *arg, int *cmp, struct got_reference *ref1,
    struct got_reference *ref2)
{
	const struct got_error *err = NULL;
	struct got_repository *repo = arg;
	struct got_object_id *id1, *id2 = NULL;
	struct got_tag_object *tag1 = NULL, *tag2 = NULL;
	time_t time1, time2;

	*cmp = 0;

	err = got_ref_resolve(&id1, repo, ref1);
	if (err)
		return err;
	err = got_object_open_as_tag(&tag1, repo, id1);
	if (err)
		goto done;

	err = got_ref_resolve(&id2, repo, ref2);
	if (err)
		goto done;
	err = got_object_open_as_tag(&tag2, repo, id2);
	if (err)
		goto done;

	time1 = got_object_tag_get_tagger_time(tag1);
	time2 = got_object_tag_get_tagger_time(tag2);

	/* Put latest tags first. */
	if (time1 < time2)
		*cmp = 1;
	else if (time1 > time2)
		*cmp = -1;
	else
		err = got_ref_cmp_by_name(NULL, cmp, ref2, ref1);
done:
	free(id1);
	free(id2);
	if (tag1)
		got_object_tag_close(tag1);
	if (tag2)
		got_object_tag_close(tag2);
	return err;
}

int
gw_get_repo_log_count(struct trans *gw_trans, char *start_commit)
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	struct got_reflist_head refs;
	struct got_commit_object *commit = NULL;
	struct got_object_id *id = NULL;
	struct got_commit_graph *graph = NULL;
	char *in_repo_path = NULL, *path = NULL;
	int log_count = 0;

	error = got_repo_open(&repo, gw_trans->repo_path, NULL);
	if (error != NULL)
		return 0;

	SIMPLEQ_INIT(&refs);

	if (start_commit == NULL) {
		struct got_reference *head_ref;
		error = got_ref_open(&head_ref, repo, gw_trans->headref, 0);
		if (error != NULL)
			goto done;

		error = got_ref_resolve(&id, repo, head_ref);
		got_ref_close(head_ref);
		if (error != NULL)
			goto done;

		error = got_object_open_as_commit(&commit, repo, id);
	} else {
		struct got_reference *ref;
		error = got_ref_open(&ref, repo, start_commit, 0);
		if (error == NULL) {
			int obj_type;
			error = got_ref_resolve(&id, repo, ref);
			got_ref_close(ref);
			if (error != NULL)
				goto done;
			error = got_object_get_type(&obj_type, repo, id);
			if (error != NULL)
				goto done;
			if (obj_type == GOT_OBJ_TYPE_TAG) {
				struct got_tag_object *tag;
				error = got_object_open_as_tag(&tag, repo, id);
				if (error != NULL)
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
			error = got_object_open_as_commit(&commit, repo, id);
			if (error != NULL)
				goto done;
		}
		if (commit == NULL) {
			error = got_repo_match_object_id_prefix(&id,
			    start_commit, GOT_OBJ_TYPE_COMMIT, repo);
			if (error != NULL)
				goto done;
		}
		error = got_repo_match_object_id_prefix(&id,
			    start_commit, GOT_OBJ_TYPE_COMMIT, repo);
			if (error != NULL)
				goto done;
	}

	error = got_object_open_as_commit(&commit, repo, id);
	if (error != NULL)
		goto done;

	error = got_repo_map_path(&in_repo_path, repo, gw_trans->repo_path, 1);
	if (error != NULL)
		goto done;

	if (in_repo_path) {
		free(path);
		path = in_repo_path;
	}

	error = got_ref_list(&refs, repo, NULL, got_ref_cmp_by_name, NULL);
	if (error)
		goto done;

	error = got_commit_graph_open(&graph, path, 0);
	if (error)
		goto done;

	error = got_commit_graph_iter_start(graph, id, repo, NULL, NULL);
	if (error)
		goto done;

	for (;;) {
		error = got_commit_graph_iter_next(&id, graph, repo, NULL,
		    NULL);
		if (error) {
			if (error->code == GOT_ERR_ITER_COMPLETED)
				error = NULL;
			break;
		}
		if (id == NULL)
			break;

		if (error)
			break;
		log_count++;
	}
done:
	if (graph)
		got_commit_graph_close(graph);
	if (repo) {
		error = got_repo_close(repo);
		if (error != NULL)
			return 0;
	}
	if (error) {
		khttp_puts(gw_trans->gw_req, "Error: ");
		khttp_puts(gw_trans->gw_req, error->msg);
		return 0;
	} else
		return log_count;
}

static const struct got_error *
gw_blame(struct trans *gw_trans)
{
	const struct got_error *error = NULL;

	return error;
}

static const struct got_error *
gw_blob(struct trans *gw_trans)
{
	const struct got_error *error = NULL;

	return error;
}

static const struct got_error *
gw_blobdiff(struct trans *gw_trans)
{
	const struct got_error *error = NULL;

	return error;
}

static const struct got_error *
gw_commit(struct trans *gw_trans)
{
	const struct got_error *error = NULL;
	char *log, *log_html;

	error = apply_unveil(gw_trans->gw_dir->path, NULL);
	if (error)
		return error;

	log = gw_get_repo_log(gw_trans, NULL, gw_trans->commit, 1, LOGCOMMIT);

	if (log != NULL && strcmp(log, "") != 0) {
		if ((asprintf(&log_html, log_commit, log)) == -1)
			return got_error_from_errno("asprintf");
		khttp_puts(gw_trans->gw_req, log_html);
		free(log_html);
		free(log);
	}
	return error;
}

static const struct got_error *
gw_commitdiff(struct trans *gw_trans)
{
	const struct got_error *error = NULL;
	char *log, *log_html;

	error = apply_unveil(gw_trans->gw_dir->path, NULL);
	if (error)
		return error;

	log = gw_get_repo_log(gw_trans, NULL, gw_trans->commit, 1, LOGDIFF);

	if (log != NULL && strcmp(log, "") != 0) {
		if ((asprintf(&log_html, log_diff, log)) == -1)
			return got_error_from_errno("asprintf");
		khttp_puts(gw_trans->gw_req, log_html);
		free(log_html);
		free(log);
	}
	return error;
}

static const struct got_error *
gw_history(struct trans *gw_trans)
{
	const struct got_error *error = NULL;

	return error;
}

static const struct got_error *
gw_index(struct trans *gw_trans)
{
	const struct got_error *error = NULL;
	struct gw_dir *gw_dir = NULL;
	char *html, *navs, *next, *prev;
	unsigned int prev_disp = 0, next_disp = 1, dir_c = 0;

	error = apply_unveil(gw_trans->gw_conf->got_repos_path, NULL);
	if (error)
		return error;

	error = gw_load_got_paths(gw_trans);
	if (error)
		return error;

	khttp_puts(gw_trans->gw_req, index_projects_header);

	TAILQ_FOREACH(gw_dir, &gw_trans->gw_dirs, entry)
		dir_c++;

	TAILQ_FOREACH(gw_dir, &gw_trans->gw_dirs, entry) {
		if (gw_trans->page > 0 && (gw_trans->page *
		    gw_trans->gw_conf->got_max_repos_display) > prev_disp) {
			prev_disp++;
			continue;
		}

		prev_disp++;
		if((asprintf(&navs, index_navs, gw_dir->name, gw_dir->name,
		    gw_dir->name, gw_dir->name)) == -1)
			return got_error_from_errno("asprintf");

		if ((asprintf(&html, index_projects, gw_dir->name, gw_dir->name,
		    gw_dir->description, gw_dir->owner, gw_dir->age,
		    navs)) == -1)
			return got_error_from_errno("asprintf");

		khttp_puts(gw_trans->gw_req, html);

		free(navs);
		free(html);

		if (gw_trans->gw_conf->got_max_repos_display == 0)
			continue;

		if (next_disp == gw_trans->gw_conf->got_max_repos_display)
			khttp_puts(gw_trans->gw_req, np_wrapper_start);
		else if ((gw_trans->gw_conf->got_max_repos_display > 0) &&
		    (gw_trans->page > 0) &&
		    (next_disp == gw_trans->gw_conf->got_max_repos_display ||
		    prev_disp == gw_trans->repos_total))
			khttp_puts(gw_trans->gw_req, np_wrapper_start);

		if ((gw_trans->gw_conf->got_max_repos_display > 0) &&
		    (gw_trans->page > 0) &&
		    (next_disp == gw_trans->gw_conf->got_max_repos_display ||
		    prev_disp == gw_trans->repos_total)) {
			if ((asprintf(&prev, nav_prev,
			    gw_trans->page - 1)) == -1)
				return got_error_from_errno("asprintf");
			khttp_puts(gw_trans->gw_req, prev);
			free(prev);
		}

		khttp_puts(gw_trans->gw_req, div_end);

		if (gw_trans->gw_conf->got_max_repos_display > 0 &&
		    next_disp == gw_trans->gw_conf->got_max_repos_display &&
		    dir_c != (gw_trans->page + 1) *
		    gw_trans->gw_conf->got_max_repos_display) {
			if ((asprintf(&next, nav_next,
			    gw_trans->page + 1)) == -1)
				return got_error_from_errno("calloc");
			khttp_puts(gw_trans->gw_req, next);
			khttp_puts(gw_trans->gw_req, div_end);
			free(next);
			next_disp = 0;
			break;
		}

		if ((gw_trans->gw_conf->got_max_repos_display > 0) &&
		    (gw_trans->page > 0) &&
		    (next_disp == gw_trans->gw_conf->got_max_repos_display ||
		    prev_disp == gw_trans->repos_total))
			khttp_puts(gw_trans->gw_req, div_end);

		next_disp++;
	}
	return error;
}

static const struct got_error *
gw_log(struct trans *gw_trans)
{
	const struct got_error *error = NULL;
	char *log, *log_html;

	error = apply_unveil(gw_trans->gw_dir->path, NULL);
	if (error)
		return error;

	log = gw_get_repo_log(gw_trans, NULL, gw_trans->commit,
	    gw_trans->gw_conf->got_max_commits_display, LOGFULL);

	if (log != NULL && strcmp(log, "") != 0) {
		if ((asprintf(&log_html, logs, log)) == -1)
			return got_error_from_errno("asprintf");
		khttp_puts(gw_trans->gw_req, log_html);
		free(log_html);
		free(log);
	}
	return error;
}

static const struct got_error *
gw_raw(struct trans *gw_trans)
{
	const struct got_error *error = NULL;

	return error;
}

static const struct got_error *
gw_logbriefs(struct trans *gw_trans)
{
	const struct got_error *error = NULL;
	char *log, *log_html;

	error = apply_unveil(gw_trans->gw_dir->path, NULL);
	if (error)
		return error;

	log = gw_get_repo_log(gw_trans, NULL, gw_trans->commit,
	    gw_trans->gw_conf->got_max_commits_display, LOGBRIEF);

	if (log != NULL && strcmp(log, "") != 0) {
		if ((asprintf(&log_html, summary_logbriefs,
		    log)) == -1)
			return got_error_from_errno("asprintf");
		khttp_puts(gw_trans->gw_req, log_html);
		free(log_html);
		free(log);
	}
	return error;
}

static const struct got_error *
gw_snapshot(struct trans *gw_trans)
{
	const struct got_error *error = NULL;

	return error;
}

static const struct got_error *
gw_summary(struct trans *gw_trans)
{
	const struct got_error *error = NULL;
	char *description_html, *repo_owner_html, *repo_age_html,
	     *cloneurl_html, *log, *log_html, *tags, *heads, *tags_html,
	     *heads_html, *age;

	error = apply_unveil(gw_trans->gw_dir->path, NULL);
	if (error)
		return error;

	khttp_puts(gw_trans->gw_req, summary_wrapper);
	if (gw_trans->gw_conf->got_show_repo_description) {
		if (gw_trans->gw_dir->description != NULL &&
		    (strcmp(gw_trans->gw_dir->description, "") != 0)) {
			if ((asprintf(&description_html, description,
			    gw_trans->gw_dir->description)) == -1)
				return got_error_from_errno("asprintf");

			khttp_puts(gw_trans->gw_req, description_html);
			free(description_html);
		}
	}

	if (gw_trans->gw_conf->got_show_repo_owner) {
		if (gw_trans->gw_dir->owner != NULL &&
		    (strcmp(gw_trans->gw_dir->owner, "") != 0)) {
			if ((asprintf(&repo_owner_html, repo_owner,
			    gw_trans->gw_dir->owner)) == -1)
				return got_error_from_errno("asprintf");

			khttp_puts(gw_trans->gw_req, repo_owner_html);
			free(repo_owner_html);
		}
	}

	if (gw_trans->gw_conf->got_show_repo_age) {
		age = gw_get_repo_age(gw_trans, gw_trans->gw_dir->path,
		    "refs/heads", TM_LONG);
		if (age != NULL && (strcmp(age, "") != 0)) {
			if ((asprintf(&repo_age_html, last_change, age)) == -1)
				return got_error_from_errno("asprintf");

			khttp_puts(gw_trans->gw_req, repo_age_html);
			free(repo_age_html);
			free(age);
		}
	}

	if (gw_trans->gw_conf->got_show_repo_cloneurl) {
		if (gw_trans->gw_dir->url != NULL &&
		    (strcmp(gw_trans->gw_dir->url, "") != 0)) {
			if ((asprintf(&cloneurl_html, cloneurl,
			    gw_trans->gw_dir->url)) == -1)
				return got_error_from_errno("asprintf");

			khttp_puts(gw_trans->gw_req, cloneurl_html);
			free(cloneurl_html);
		}
	}
	khttp_puts(gw_trans->gw_req, div_end);

	log = gw_get_repo_log(gw_trans, NULL, NULL, D_MAXSLCOMMDISP, 0);
	tags = gw_get_repo_tags(gw_trans, D_MAXSLCOMMDISP, TAGBRIEF);
	heads = gw_get_repo_heads(gw_trans);

	if (log != NULL && strcmp(log, "") != 0) {
		if ((asprintf(&log_html, summary_logbriefs,
		    log)) == -1)
			return got_error_from_errno("asprintf");
		khttp_puts(gw_trans->gw_req, log_html);
		free(log_html);
		free(log);
	}

	if (tags != NULL && strcmp(tags, "") != 0) {
		if ((asprintf(&tags_html, summary_tags,
		    tags)) == -1)
			return got_error_from_errno("asprintf");
		khttp_puts(gw_trans->gw_req, tags_html);
		free(tags_html);
		free(tags);
	}

	if (heads != NULL && strcmp(heads, "") != 0) {
		if ((asprintf(&heads_html, summary_heads,
		    heads)) == -1)
			return got_error_from_errno("asprintf");
		khttp_puts(gw_trans->gw_req, heads_html);
		free(heads_html);
		free(heads);
	}
	return error;
}

static const struct got_error *
gw_tag(struct trans *gw_trans)
{
	const struct got_error *error = NULL;
	char *log, *log_html;

	error = apply_unveil(gw_trans->gw_dir->path, NULL);
	if (error)
		return error;

	log = gw_get_repo_log(gw_trans, NULL, gw_trans->commit, 1, LOGTAG);

	if (log != NULL && strcmp(log, "") != 0) {
		if ((asprintf(&log_html, log_tag, log)) == -1)
			return got_error_from_errno("asprintf");
		khttp_puts(gw_trans->gw_req, log_html);
		free(log_html);
		free(log);
	}
	return error;
}

static const struct got_error *
gw_tree(struct trans *gw_trans)
{
	const struct got_error *error = NULL;
	char *log, *log_html;

	error = apply_unveil(gw_trans->gw_dir->path, NULL);
	if (error)
		return error;

	log = gw_get_repo_log(gw_trans, NULL, gw_trans->commit, 1, LOGTREE);

	if (log != NULL && strcmp(log, "") != 0) {
		if ((asprintf(&log_html, log_tree, log)) == -1)
			return got_error_from_errno("asprintf");
		khttp_puts(gw_trans->gw_req, log_html);
		free(log_html);
		free(log);
	}
	return error;
}

static const struct got_error *
gw_load_got_path(struct trans *gw_trans, struct gw_dir *gw_dir)
{
	const struct got_error *error = NULL;
	DIR *dt;
	char *dir_test;
	int opened = 0;

	if ((asprintf(&dir_test, "%s/%s/%s",
	    gw_trans->gw_conf->got_repos_path, gw_dir->name,
	    GOTWEB_GIT_DIR)) == -1)
		return got_error_from_errno("asprintf");

	dt = opendir(dir_test);
	if (dt == NULL) {
		free(dir_test);
	} else {
		gw_dir->path = strdup(dir_test);
		opened = 1;
		goto done;
	}

	if ((asprintf(&dir_test, "%s/%s/%s",
	    gw_trans->gw_conf->got_repos_path, gw_dir->name,
	    GOTWEB_GOT_DIR)) == -1)
		return got_error_from_errno("asprintf");

	dt = opendir(dir_test);
	if (dt == NULL)
		free(dir_test);
	else {
		opened = 1;
		error = got_error(GOT_ERR_NOT_GIT_REPO);
		goto errored;
	}

	if ((asprintf(&dir_test, "%s/%s",
	    gw_trans->gw_conf->got_repos_path, gw_dir->name)) == -1)
		return got_error_from_errno("asprintf");

	gw_dir->path = strdup(dir_test);

done:
	gw_dir->description = gw_get_repo_description(gw_trans,
	    gw_dir->path);
	gw_dir->owner = gw_get_repo_owner(gw_trans, gw_dir->path);
	gw_dir->age = gw_get_repo_age(gw_trans, gw_dir->path, "refs/heads",
	    TM_DIFF);
	gw_dir->url = gw_get_clone_url(gw_trans, gw_dir->path);

errored:
	free(dir_test);
	if (opened)
		closedir(dt);
	return error;
}

static const struct got_error *
gw_load_got_paths(struct trans *gw_trans)
{
	const struct got_error *error = NULL;
	DIR *d;
	struct dirent **sd_dent;
	struct gw_dir *gw_dir;
	struct stat st;
	unsigned int d_cnt, d_i;

	d = opendir(gw_trans->gw_conf->got_repos_path);
	if (d == NULL) {
		error = got_error_from_errno2("opendir",
		    gw_trans->gw_conf->got_repos_path);
		return error;
	}

	d_cnt = scandir(gw_trans->gw_conf->got_repos_path, &sd_dent, NULL,
	    alphasort);
	if (d_cnt == -1) {
		error = got_error_from_errno2("scandir",
		    gw_trans->gw_conf->got_repos_path);
		return error;
	}

	for (d_i = 0; d_i < d_cnt; d_i++) {
		if (gw_trans->gw_conf->got_max_repos > 0 &&
		    (d_i - 2) == gw_trans->gw_conf->got_max_repos)
			break; /* account for parent and self */

		if (strcmp(sd_dent[d_i]->d_name, ".") == 0 ||
		    strcmp(sd_dent[d_i]->d_name, "..") == 0)
			continue;

		if ((gw_dir = gw_init_gw_dir(sd_dent[d_i]->d_name)) == NULL)
			return got_error_from_errno("gw_dir malloc");

		error = gw_load_got_path(gw_trans, gw_dir);
		if (error && error->code == GOT_ERR_NOT_GIT_REPO)
			continue;
		else if (error)
			return error;

		if (lstat(gw_dir->path, &st) == 0 && S_ISDIR(st.st_mode) &&
		    !got_path_dir_is_empty(gw_dir->path)) {
			TAILQ_INSERT_TAIL(&gw_trans->gw_dirs, gw_dir,
			    entry);
			gw_trans->repos_total++;
		}
	}

	closedir(d);
	return error;
}

static const struct got_error *
gw_parse_querystring(struct trans *gw_trans)
{
	const struct got_error *error = NULL;
	struct kpair *p;
	struct gw_query_action *action = NULL;
	unsigned int i;

	if (gw_trans->gw_req->fieldnmap[0]) {
		error = got_error_from_errno("bad parse");
		return error;
	} else if ((p = gw_trans->gw_req->fieldmap[KEY_PATH])) {
		/* define gw_trans->repo_path */
		if ((asprintf(&gw_trans->repo_name, "%s", p->parsed.s)) == -1)
			return got_error_from_errno("asprintf");

		if ((asprintf(&gw_trans->repo_path, "%s/%s",
		    gw_trans->gw_conf->got_repos_path, p->parsed.s)) == -1)
			return got_error_from_errno("asprintf");

 		if ((p = gw_trans->gw_req->fieldmap[KEY_COMMIT_ID]))
			if ((asprintf(&gw_trans->commit, "%s",
			    p->parsed.s)) == -1)
				return got_error_from_errno("asprintf");

		/* get action and set function */
		if ((p = gw_trans->gw_req->fieldmap[KEY_ACTION]))
			for (i = 0; i < nitems(gw_query_funcs); i++) {
				action = &gw_query_funcs[i];
				if (action->func_name == NULL)
					continue;

				if (strcmp(action->func_name,
				    p->parsed.s) == 0) {
					gw_trans->action = i;
					if ((asprintf(&gw_trans->action_name,
					    "%s", action->func_name)) == -1)
						return
						    got_error_from_errno(
						    "asprintf");

					break;
				}

				action = NULL;
			}

		if ((p = gw_trans->gw_req->fieldmap[KEY_FILE]))
			if ((asprintf(&gw_trans->repo_file, "%s",
			    p->parsed.s)) == -1)
				return got_error_from_errno("asprintf");

		if ((p = gw_trans->gw_req->fieldmap[KEY_HEADREF]))
			if ((asprintf(&gw_trans->headref, "%s",
			    p->parsed.s)) == -1)
				return got_error_from_errno("asprintf");

		if (action == NULL) {
			error = got_error_from_errno("invalid action");
			return error;
		}
		if ((gw_trans->gw_dir =
		    gw_init_gw_dir(gw_trans->repo_name)) == NULL)
			return got_error_from_errno("gw_dir malloc");

		error = gw_load_got_path(gw_trans, gw_trans->gw_dir);
		if (error)
			return error;
	} else
		gw_trans->action = GW_INDEX;

	if ((p = gw_trans->gw_req->fieldmap[KEY_PAGE]))
		gw_trans->page = p->parsed.i;

	if (gw_trans->action == GW_RAW)
		gw_trans->mime = KMIME_TEXT_PLAIN;

	return error;
}

static struct gw_dir *
gw_init_gw_dir(char *dir)
{
	struct gw_dir *gw_dir;

	if ((gw_dir = malloc(sizeof(*gw_dir))) == NULL)
		return NULL;

	if ((asprintf(&gw_dir->name, "%s", dir)) == -1)
		return NULL;

	return gw_dir;
}

static const struct got_error*
match_logmsg(int *have_match, struct got_object_id *id,
    struct got_commit_object *commit, regex_t *regex)
{
	const struct got_error *err = NULL;
	regmatch_t regmatch;
	char *id_str = NULL, *logmsg = NULL;

	*have_match = 0;

	err = got_object_id_str(&id_str, id);
	if (err)
		return err;

	err = got_object_commit_get_logmsg(&logmsg, commit);
	if (err)
		goto done;

	if (regexec(regex, logmsg, 1, &regmatch, 0) == 0)
		*have_match = 1;
done:
	free(id_str);
	free(logmsg);
	return err;
}

static void
gw_display_open(struct trans *gw_trans, enum khttp code, enum kmime mime)
{
	khttp_head(gw_trans->gw_req, kresps[KRESP_ALLOW], "GET");
	khttp_head(gw_trans->gw_req, kresps[KRESP_STATUS], "%s",
	    khttps[code]);
	khttp_head(gw_trans->gw_req, kresps[KRESP_CONTENT_TYPE], "%s",
	    kmimetypes[mime]);
	khttp_head(gw_trans->gw_req, "X-Content-Type-Options", "nosniff");
	khttp_head(gw_trans->gw_req, "X-Frame-Options", "DENY");
	khttp_head(gw_trans->gw_req, "X-XSS-Protection", "1; mode=block");
	khttp_body(gw_trans->gw_req);
}

static void
gw_display_index(struct trans *gw_trans, const struct got_error *err)
{
	gw_display_open(gw_trans, KHTTP_200, gw_trans->mime);
	khtml_open(gw_trans->gw_html_req, gw_trans->gw_req, 0);

	if (err)
		khttp_puts(gw_trans->gw_req, err->msg);
	else
		khttp_template(gw_trans->gw_req, gw_trans->gw_tmpl,
		    gw_query_funcs[gw_trans->action].template);

	khtml_close(gw_trans->gw_html_req);
}

static int
gw_template(size_t key, void *arg)
{
	const struct got_error *error = NULL;
	struct trans *gw_trans = arg;
	char *gw_got_link, *gw_site_link;
	char *site_owner_name, *site_owner_name_h;

	switch (key) {
	case (TEMPL_HEAD):
		khttp_puts(gw_trans->gw_req, head);
		break;
	case(TEMPL_HEADER):
		gw_got_link = gw_get_got_link(gw_trans);
		if (gw_got_link != NULL)
			khttp_puts(gw_trans->gw_req, gw_got_link);

		free(gw_got_link);
		break;
	case (TEMPL_SITEPATH):
		gw_site_link = gw_get_site_link(gw_trans);
		if (gw_site_link != NULL)
			khttp_puts(gw_trans->gw_req, gw_site_link);

		free(gw_site_link);
		break;
	case(TEMPL_TITLE):
		if (gw_trans->gw_conf->got_site_name != NULL)
			khtml_puts(gw_trans->gw_html_req,
			    gw_trans->gw_conf->got_site_name);

		break;
	case (TEMPL_SEARCH):
		khttp_puts(gw_trans->gw_req, search);
		break;
	case(TEMPL_SITEOWNER):
		if (gw_trans->gw_conf->got_site_owner != NULL &&
		    gw_trans->gw_conf->got_show_site_owner) {
			site_owner_name =
			    gw_html_escape(gw_trans->gw_conf->got_site_owner);
			if ((asprintf(&site_owner_name_h, site_owner,
			    site_owner_name))
			    == -1)
				return 0;

			khttp_puts(gw_trans->gw_req, site_owner_name_h);
			free(site_owner_name);
			free(site_owner_name_h);
		}
		break;
	case(TEMPL_CONTENT):
		error = gw_query_funcs[gw_trans->action].func_main(gw_trans);
		if (error)
			khttp_puts(gw_trans->gw_req, error->msg);

		break;
	default:
		return 0;
		break;
	}
	return 1;
}

static char *
gw_get_repo_description(struct trans *gw_trans, char *dir)
{
	FILE *f;
	char *description = NULL, *d_file = NULL;
	unsigned int len;

	if (gw_trans->gw_conf->got_show_repo_description == false)
		goto err;

	if ((asprintf(&d_file, "%s/description", dir)) == -1)
		goto err;

	if ((f = fopen(d_file, "r")) == NULL)
		goto err;

	fseek(f, 0, SEEK_END);
	len = ftell(f) + 1;
	fseek(f, 0, SEEK_SET);
	if ((description = calloc(len, sizeof(char *))) == NULL)
		goto err;

	fread(description, 1, len, f);
	fclose(f);
	free(d_file);
	return description;
err:
	if ((asprintf(&description, "%s", "")) == -1)
		return NULL;

	return description;
}

static char *
gw_get_time_str(time_t committer_time, int ref_tm)
{
	struct tm tm;
	time_t diff_time;
	char *years = "years ago", *months = "months ago";
	char *weeks = "weeks ago", *days = "days ago", *hours = "hours ago";
	char *minutes = "minutes ago", *seconds = "seconds ago";
	char *now = "right now";
	char *repo_age, *s;
	char datebuf[29];

	switch (ref_tm) {
	case TM_DIFF:
		diff_time = time(NULL) - committer_time;
		if (diff_time > 60 * 60 * 24 * 365 * 2) {
			if ((asprintf(&repo_age, "%lld %s",
			    (diff_time / 60 / 60 / 24 / 365), years)) == -1)
				return NULL;
		} else if (diff_time > 60 * 60 * 24 * (365 / 12) * 2) {
			if ((asprintf(&repo_age, "%lld %s",
			    (diff_time / 60 / 60 / 24 / (365 / 12)),
			    months)) == -1)
				return NULL;
		} else if (diff_time > 60 * 60 * 24 * 7 * 2) {
			if ((asprintf(&repo_age, "%lld %s",
			    (diff_time / 60 / 60 / 24 / 7), weeks)) == -1)
				return NULL;
		} else if (diff_time > 60 * 60 * 24 * 2) {
			if ((asprintf(&repo_age, "%lld %s",
			    (diff_time / 60 / 60 / 24), days)) == -1)
				return NULL;
		} else if (diff_time > 60 * 60 * 2) {
			if ((asprintf(&repo_age, "%lld %s",
			    (diff_time / 60 / 60), hours)) == -1)
				return NULL;
		} else if (diff_time > 60 * 2) {
			if ((asprintf(&repo_age, "%lld %s", (diff_time / 60),
			    minutes)) == -1)
				return NULL;
		} else if (diff_time > 2) {
			if ((asprintf(&repo_age, "%lld %s", diff_time,
			    seconds)) == -1)
				return NULL;
		} else {
			if ((asprintf(&repo_age, "%s", now)) == -1)
				return NULL;
		}
		break;
	case TM_LONG:
		if (gmtime_r(&committer_time, &tm) == NULL)
			return NULL;

		s = asctime_r(&tm, datebuf);
		if (s == NULL)
			return NULL;

		if ((asprintf(&repo_age, "%s UTC", datebuf)) == -1)
			return NULL;
		break;
	}
	return repo_age;
}

static char *
gw_get_repo_age(struct trans *gw_trans, char *dir, char *repo_ref, int ref_tm)
{
	const struct got_error *error = NULL;
	struct got_object_id *id = NULL;
	struct got_repository *repo = NULL;
	struct got_commit_object *commit = NULL;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;
	struct got_reference *head_ref;
	int is_head = 0;
	time_t committer_time = 0, cmp_time = 0;
	const char *refname;
	char *repo_age = NULL;

	if (repo_ref == NULL)
		return NULL;

	if (strncmp(repo_ref, "refs/heads/", 11) == 0)
		is_head = 1;

	SIMPLEQ_INIT(&refs);
	if (gw_trans->gw_conf->got_show_repo_age == false) {
		if ((asprintf(&repo_age, "")) == -1)
			return NULL;
		return repo_age;
	}

	error = got_repo_open(&repo, dir, NULL);
	if (error != NULL)
		goto err;

	if (is_head)
		error = got_ref_list(&refs, repo, "refs/heads",
		    got_ref_cmp_by_name, NULL);
	else
		error = got_ref_list(&refs, repo, repo_ref,
		    got_ref_cmp_by_name, NULL);
	if (error != NULL)
		goto err;

	SIMPLEQ_FOREACH(re, &refs, entry) {
		if (is_head)
			refname = strdup(repo_ref);
		else
			refname = got_ref_get_name(re->ref);
		error = got_ref_open(&head_ref, repo, refname, 0);
		if (error != NULL)
			goto err;

		error = got_ref_resolve(&id, repo, head_ref);
		got_ref_close(head_ref);
		if (error != NULL)
			goto err;

		error = got_object_open_as_commit(&commit, repo, id);
		if (error != NULL)
			goto err;

		committer_time =
		    got_object_commit_get_committer_time(commit);

		if (cmp_time < committer_time)
			cmp_time = committer_time;
	}

	if (cmp_time != 0) {
		committer_time = cmp_time;
		repo_age = gw_get_time_str(committer_time, ref_tm);
	} else
		if ((asprintf(&repo_age, "")) == -1)
			return NULL;
	got_ref_list_free(&refs);
	free(id);
	return repo_age;
err:
	if ((asprintf(&repo_age, "%s", error->msg)) == -1)
		return NULL;

	return repo_age;
}

static char *
gw_get_repo_owner(struct trans *gw_trans, char *dir)
{
	FILE *f;
	char *owner = NULL, *d_file = NULL;
	char *gotweb = "[gotweb]", *gitweb = "[gitweb]", *gw_owner = "owner";
	char *comp, *pos, *buf;
	unsigned int i;

	if (gw_trans->gw_conf->got_show_repo_owner == false)
		goto err;

	if ((asprintf(&d_file, "%s/config", dir)) == -1)
		goto err;

	if ((f = fopen(d_file, "r")) == NULL)
		goto err;

	if ((buf = calloc(128, sizeof(char *))) == NULL)
		goto err;

	while ((fgets(buf, 128, f)) != NULL) {
		if ((pos = strstr(buf, gotweb)) != NULL)
			break;

		if ((pos = strstr(buf, gitweb)) != NULL)
			break;
	}

	if (pos == NULL)
		goto err;

	do {
		fgets(buf, 128, f);
	} while ((comp = strcasestr(buf, gw_owner)) == NULL);

	if (comp == NULL)
		goto err;

	if (strncmp(gw_owner, comp, strlen(gw_owner)) != 0)
		goto err;

	for (i = 0; i < 2; i++) {
		owner = strsep(&buf, "\"");
	}

	if (owner == NULL)
		goto err;

	fclose(f);
	free(d_file);
	return owner;
err:
	if ((asprintf(&owner, "%s", "")) == -1)
		return NULL;

	return owner;
}

static char *
gw_get_clone_url(struct trans *gw_trans, char *dir)
{
	FILE *f;
	char *url = NULL, *d_file = NULL;
	unsigned int len;

	if ((asprintf(&d_file, "%s/cloneurl", dir)) == -1)
		return NULL;

	if ((f = fopen(d_file, "r")) == NULL)
		return NULL;

	fseek(f, 0, SEEK_END);
	len = ftell(f) + 1;
	fseek(f, 0, SEEK_SET);

	if ((url = calloc(len, sizeof(char *))) == NULL)
		return NULL;

	fread(url, 1, len, f);
	fclose(f);
	free(d_file);
	return url;
}

static char *
gw_get_repo_log(struct trans *gw_trans, const char *search_pattern,
    char *start_commit, int limit, int log_type)
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;
	struct got_commit_object *commit = NULL;
	struct got_object_id *id1 = NULL, *id2 = NULL;
	struct got_object_qid *parent_id;
	struct got_commit_graph *graph = NULL;
	char *logs = NULL, *id_str1 = NULL, *id_str2 = NULL, *path = NULL,
	     *in_repo_path = NULL, *refs_str = NULL, *refs_str_disp = NULL,
	     *treeid = NULL, *commit_row = NULL, *commit_commit = NULL,
	     *commit_commit_disp = NULL, *commit_age_diff = NULL,
	     *commit_age_diff_disp = NULL, *commit_age_long = NULL,
	     *commit_age_long_disp = NULL, *commit_author = NULL,
	     *commit_author_disp = NULL, *commit_committer = NULL,
	     *commit_committer_disp = NULL, *commit_log = NULL,
	     *commit_log_disp = NULL, *commit_parent = NULL,
	     *commit_diff_disp = NULL, *logbriefs_navs_html = NULL,
	     *log_tree_html = NULL, *log_commit_html = NULL,
	     *log_diff_html = NULL, *commit_tree = NULL,
	     *commit_tree_disp = NULL, *log_tag_html = NULL;
	char *commit_log0, *newline;
	regex_t regex;
	int have_match, log_count = 0;
	size_t newsize;
	struct buf *diffbuf = NULL;
	time_t committer_time;

	if (gw_trans->action == GW_LOG || gw_trans->action == GW_LOGBRIEFS)
		log_count = gw_get_repo_log_count(gw_trans, start_commit);

	error = buf_alloc(&diffbuf, 0);
	if (error != NULL)
		return NULL;

	if (search_pattern &&
	    regcomp(&regex, search_pattern, REG_EXTENDED | REG_NOSUB |
	    REG_NEWLINE))
		return NULL;

	error = got_repo_open(&repo, gw_trans->repo_path, NULL);
	if (error != NULL)
		return NULL;

	SIMPLEQ_INIT(&refs);

	if (start_commit == NULL) {
		struct got_reference *head_ref;
		error = got_ref_open(&head_ref, repo, gw_trans->headref, 0);
		if (error != NULL)
			goto done;

		error = got_ref_resolve(&id1, repo, head_ref);
		got_ref_close(head_ref);
		if (error != NULL)
			goto done;

		error = got_object_open_as_commit(&commit, repo, id1);
	} else {
		struct got_reference *ref;
		error = got_ref_open(&ref, repo, start_commit, 0);
		if (error == NULL) {
			int obj_type;
			error = got_ref_resolve(&id1, repo, ref);
			got_ref_close(ref);
			if (error != NULL)
				goto done;
			error = got_object_get_type(&obj_type, repo, id1);
			if (error != NULL)
				goto done;
			if (obj_type == GOT_OBJ_TYPE_TAG) {
				struct got_tag_object *tag;
				error = got_object_open_as_tag(&tag, repo, id1);
				if (error != NULL)
					goto done;
				if (got_object_tag_get_object_type(tag) !=
				    GOT_OBJ_TYPE_COMMIT) {
					got_object_tag_close(tag);
					error = got_error(GOT_ERR_OBJ_TYPE);
					goto done;
				}
				free(id1);
				id1 = got_object_id_dup(
				    got_object_tag_get_object_id(tag));
				if (id1 == NULL)
					error = got_error_from_errno(
					    "got_object_id_dup");
				got_object_tag_close(tag);
				if (error)
					goto done;
			} else if (obj_type != GOT_OBJ_TYPE_COMMIT) {
				error = got_error(GOT_ERR_OBJ_TYPE);
				goto done;
			}
			error = got_object_open_as_commit(&commit, repo, id1);
			if (error != NULL)
				goto done;
		}
		if (commit == NULL) {
			error = got_repo_match_object_id_prefix(&id1,
			    start_commit, GOT_OBJ_TYPE_COMMIT, repo);
			if (error != NULL)
				goto done;
		}
		error = got_repo_match_object_id_prefix(&id1,
			    start_commit, GOT_OBJ_TYPE_COMMIT, repo);
	}

	if (error != NULL)
		goto done;

	error = got_repo_map_path(&in_repo_path, repo, gw_trans->repo_path, 1);
	if (error != NULL)
		goto done;

	if (in_repo_path) {
		free(path);
		path = in_repo_path;
	}

	error = got_ref_list(&refs, repo, NULL, got_ref_cmp_by_name, NULL);
	if (error)
		goto done;

	error = got_commit_graph_open(&graph, path, 0);
	if (error)
		goto done;

	error = got_commit_graph_iter_start(graph, id1, repo, NULL, NULL);
	if (error)
		goto done;

	for (;;) {
		error = got_commit_graph_iter_next(&id1, graph, repo, NULL,
		    NULL);
		if (error) {
			if (error->code == GOT_ERR_ITER_COMPLETED)
				error = NULL;
			break;
		}
		if (id1 == NULL)
			break;

		error = got_object_open_as_commit(&commit, repo, id1);
		if (error)
			break;

		if (search_pattern) {
			error = match_logmsg(&have_match, id1, commit,
			    &regex);
			if (error) {
				got_object_commit_close(commit);
				break;
			}
			if (have_match == 0) {
				got_object_commit_close(commit);
				continue;
			}
		}

		SIMPLEQ_FOREACH(re, &refs, entry) {
			char *s;
			const char *name;
			struct got_tag_object *tag = NULL;
			int cmp;

			name = got_ref_get_name(re->ref);
			if (strcmp(name, GOT_REF_HEAD) == 0)
				continue;
			if (strncmp(name, "refs/", 5) == 0)
				name += 5;
			if (strncmp(name, "got/", 4) == 0)
				continue;
			if (strncmp(name, "heads/", 6) == 0)
				name += 6;
			if (strncmp(name, "remotes/", 8) == 0)
				name += 8;
			if (strncmp(name, "tags/", 5) == 0) {
				error = got_object_open_as_tag(&tag, repo,
				    re->id);
				if (error) {
					if (error->code != GOT_ERR_OBJ_TYPE)
						continue;
					/*
					 * Ref points at something other
					 * than a tag.
					 */
					error = NULL;
					tag = NULL;
				}
			}
			cmp = got_object_id_cmp(tag ?
			    got_object_tag_get_object_id(tag) : re->id, id1);
			if (tag)
				got_object_tag_close(tag);
			if (cmp != 0)
				continue;
			s = refs_str;
			if ((asprintf(&refs_str, "%s%s%s", s ? s : "",
			    s ? ", " : "", name)) == -1) {
				error = got_error_from_errno("asprintf");
				free(s);
				goto done;
			}
			free(s);
		}

		if (refs_str == NULL)
			refs_str_disp = strdup("");
		else {
			if ((asprintf(&refs_str_disp, "(%s)",
			    refs_str)) == -1) {
				error = got_error_from_errno("asprintf");
				free(refs_str);
				goto done;
			}
		}

		error = got_object_id_str(&id_str1, id1);
		if (error)
			goto done;

		error = got_object_id_str(&treeid,
		    got_object_commit_get_tree_id(commit));
		if (error)
			goto done;

		if (gw_trans->action == GW_COMMIT ||
		    gw_trans->action == GW_COMMITDIFF) {
			parent_id =
			    SIMPLEQ_FIRST(
			    got_object_commit_get_parent_ids(commit));
			if (parent_id != NULL) {
				id2 = got_object_id_dup(parent_id->id);
				free (parent_id);
				error = got_object_id_str(&id_str2, id2);
				if (error)
					goto done;
				free(id2);
			} else
				id_str2 = strdup("/dev/null");
		}

		committer_time =
		    got_object_commit_get_committer_time(commit);

		if ((asprintf(&commit_parent, "%s", id_str2)) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}

		if ((asprintf(&commit_tree, "%s", treeid)) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}

		if ((asprintf(&commit_tree_disp, commit_tree_html,
		    treeid)) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}

		if ((asprintf(&commit_diff_disp, commit_diff_html, id_str2,
			id_str1)) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}

		if ((asprintf(&commit_commit, "%s", id_str1)) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}

		if ((asprintf(&commit_commit_disp, commit_commit_html,
		    commit_commit, refs_str_disp)) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}

		if ((asprintf(&commit_age_long, "%s",
		    gw_get_time_str(committer_time, TM_LONG))) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}

		if ((asprintf(&commit_age_long_disp, commit_age_html,
		    commit_age_long)) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}

		if ((asprintf(&commit_age_diff, "%s",
		    gw_get_time_str(committer_time, TM_DIFF))) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}

		if ((asprintf(&commit_age_diff_disp, commit_age_html,
		    commit_age_diff)) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}

		if ((asprintf(&commit_author, "%s",
		    got_object_commit_get_author(commit))) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}

		if ((asprintf(&commit_author_disp, commit_author_html,
		    gw_html_escape(commit_author))) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}

		if ((asprintf(&commit_committer, "%s",
		    got_object_commit_get_committer(commit))) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}

		if ((asprintf(&commit_committer_disp, commit_committer_html,
		    gw_html_escape(commit_committer))) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}

		if (strcmp(commit_author, commit_committer) == 0) {
			free(commit_committer_disp);
			commit_committer_disp = strdup("");
		}

		error = got_object_commit_get_logmsg(&commit_log0, commit);
		if (error)
			goto done;

		commit_log = commit_log0;
		while (*commit_log == '\n')
			commit_log++;

		switch(log_type) {
		case (LOGBRIEF):
			newline = strchr(commit_log, '\n');
			if (newline)
				*newline = '\0';

			if ((asprintf(&logbriefs_navs_html, logbriefs_navs,
			    gw_trans->repo_name, id_str1, gw_trans->repo_name,
			    id_str1, gw_trans->repo_name, id_str1,
			    gw_trans->repo_name, id_str1)) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}

			if ((asprintf(&commit_row, logbriefs_row,
			    commit_age_diff, commit_author, commit_log,
			    logbriefs_navs_html)) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}

			free(logbriefs_navs_html);
			logbriefs_navs_html = NULL;
			break;
		case (LOGFULL):
			if ((asprintf(&logbriefs_navs_html, logbriefs_navs,
			    gw_trans->repo_name, id_str1, gw_trans->repo_name,
			    id_str1, gw_trans->repo_name, id_str1,
			    gw_trans->repo_name, id_str1)) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}

			if ((asprintf(&commit_row, logs_row, commit_commit_disp,
			    commit_author_disp, commit_committer_disp,
			    commit_age_long_disp, gw_html_escape(commit_log),
			    logbriefs_navs_html)) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}

			free(logbriefs_navs_html);
			logbriefs_navs_html = NULL;
			break;
		case (LOGTAG):
			log_tag_html = strdup("tag log here");

			if ((asprintf(&commit_row, log_tag_row,
			    gw_html_escape(commit_log), log_tag_html)) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}

			free(log_tag_html);
			break;
		case (LOGTREE):
			log_tree_html = strdup("log tree here");

			if ((asprintf(&commit_row, log_tree_row,
			    gw_html_escape(commit_log), log_tree_html)) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}

			free(log_tree_html);
			break;
		case (LOGCOMMIT):
			if ((asprintf(&commit_log_disp, commit_log_html,
			    gw_html_escape(commit_log))) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}

			log_commit_html = strdup("commit here");

			if ((asprintf(&commit_row, log_commit_row,
			    commit_diff_disp, commit_commit_disp,
			    commit_tree_disp, commit_author_disp,
			    commit_committer_disp, commit_age_long_disp,
			    commit_log_disp, log_commit_html)) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}
			free(commit_log_disp);
			free(log_commit_html);

			break;
		case (LOGDIFF):
			if ((asprintf(&commit_log_disp, commit_log_html,
			    gw_html_escape(commit_log))) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}

			log_diff_html = strdup("diff here");

			if ((asprintf(&commit_row, log_diff_row,
			    commit_diff_disp, commit_commit_disp,
			    commit_tree_disp, commit_author_disp,
			    commit_committer_disp, commit_age_long_disp,
			    commit_log_disp, log_diff_html)) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}
			free(commit_log_disp);
			free(log_diff_html);

			break;
		default:
			return NULL;
		}

		error = buf_puts(&newsize, diffbuf, commit_row);

		free(commit_parent);
		free(commit_diff_disp);
		free(commit_tree_disp);
		free(commit_age_diff);
		free(commit_age_diff_disp);
		free(commit_age_long);
		free(commit_age_long_disp);
		free(commit_author);
		free(commit_author_disp);
		free(commit_committer);
		free(commit_committer_disp);
		free(commit_log0);
		free(commit_row);
		free(refs_str_disp);
		free(refs_str);
		refs_str = NULL;
		free(id_str1);
		id_str1 = NULL;
		free(id_str2);
		id_str2 = NULL;

		if (error || (limit && --limit == 0))
			break;
	}

	if (error)
		goto done;

	if (buf_len(diffbuf) > 0) {
		error = buf_putc(diffbuf, '\0');
		logs = strdup(buf_get(diffbuf));
	}
done:
	buf_free(diffbuf);
	if (commit != NULL)
		got_object_commit_close(commit);
	if (search_pattern)
		regfree(&regex);
	if (graph)
		got_commit_graph_close(graph);
	if (repo) {
		error = got_repo_close(repo);
		if (error != NULL)
			return NULL;
	}
	if (error) {
		khttp_puts(gw_trans->gw_req, "Error: ");
		khttp_puts(gw_trans->gw_req, error->msg);
		return NULL;
	} else
		return logs;
}

static char *
gw_get_repo_tags(struct trans *gw_trans, int limit, int tag_type)
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;
	char *tags = NULL, *tag_row = NULL, *tags_navs_disp = NULL,
	     *age = NULL;
	char *newline;
	struct buf *diffbuf = NULL;
	size_t newsize;

	error = buf_alloc(&diffbuf, 0);
	if (error != NULL)
		return NULL;
	SIMPLEQ_INIT(&refs);

	error = got_repo_open(&repo, gw_trans->repo_path, NULL);
	if (error != NULL)
		goto done;

	error = got_ref_list(&refs, repo, "refs/tags", cmp_tags, repo);
	if (error)
		goto done;

	SIMPLEQ_FOREACH(re, &refs, entry) {
		const char *refname;
		char *refstr, *tag_log0, *tag_log, *id_str;
		time_t tagger_time;
		struct got_object_id *id;
		struct got_tag_object *tag;

		refname = got_ref_get_name(re->ref);
		if (strncmp(refname, "refs/tags/", 10) != 0)
			continue;
		refname += 10;
		refstr = got_ref_to_str(re->ref);
		if (refstr == NULL) {
			error = got_error_from_errno("got_ref_to_str");
			goto done;
		}

		error = got_ref_resolve(&id, repo, re->ref);
		if (error)
			goto done;
		error = got_object_open_as_tag(&tag, repo, id);
		free(id);
		if (error)
			goto done;

		tagger_time = got_object_tag_get_tagger_time(tag);

		error = got_object_id_str(&id_str,
		    got_object_tag_get_object_id(tag));
		if (error)
			goto done;

		tag_log0 = strdup(got_object_tag_get_message(tag));

		if (tag_log0 == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}

		tag_log = tag_log0;
		while (*tag_log == '\n')
			tag_log++;

		switch (tag_type) {
		case TAGBRIEF:
			newline = strchr(tag_log, '\n');
			if (newline)
				*newline = '\0';

			if ((asprintf(&age, "%s", gw_get_time_str(tagger_time,
			    TM_DIFF))) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}

			if ((asprintf(&tags_navs_disp, tags_navs,
			    gw_trans->repo_name, id_str, gw_trans->repo_name,
			    id_str, gw_trans->repo_name, id_str,
			    gw_trans->repo_name, id_str)) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}

			if ((asprintf(&tag_row, tags_row, age, refname, tag_log,
			    tags_navs_disp)) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}

			free(tags_navs_disp);
			break;
		case TAGFULL:
			break;
		default:
			break;
		}

		got_object_tag_close(tag);

		error = buf_puts(&newsize, diffbuf, tag_row);

		free(id_str);
		free(refstr);
		free(age);
		free(tag_log0);
		free(tag_row);

		if (error || (limit && --limit == 0))
			break;
	}

	if (buf_len(diffbuf) > 0) {
		error = buf_putc(diffbuf, '\0');
		tags = strdup(buf_get(diffbuf));
	}
done:
	buf_free(diffbuf);
	got_ref_list_free(&refs);
	if (repo)
		got_repo_close(repo);
	if (error)
		return NULL;
	else
		return tags;
}

static char *
gw_get_repo_heads(struct trans *gw_trans)
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;
	char *heads, *head_row = NULL, *head_navs_disp = NULL, *age = NULL;
	struct buf *diffbuf = NULL;
	size_t newsize;

	error = buf_alloc(&diffbuf, 0);
	if (error != NULL)
		return NULL;

	error = got_repo_open(&repo, gw_trans->repo_path, NULL);
	if (error != NULL)
		goto done;

	SIMPLEQ_INIT(&refs);
	error = got_ref_list(&refs, repo, "refs/heads", got_ref_cmp_by_name,
	    NULL);
	if (error)
		goto done;

	SIMPLEQ_FOREACH(re, &refs, entry) {
		char *refname;

		refname = strdup(got_ref_get_name(re->ref));
		if (refname == NULL) {
			error = got_error_from_errno("got_ref_to_str");
			goto done;
		}

		if (strncmp(refname, "refs/heads/", 11) != 0) {
			free(refname);
			continue;
		}

		age = gw_get_repo_age(gw_trans, gw_trans->gw_dir->path, refname,
		    TM_DIFF);

		if ((asprintf(&head_navs_disp, heads_navs, gw_trans->repo_name,
		    refname, gw_trans->repo_name, refname,
		    gw_trans->repo_name, refname, gw_trans->repo_name,
		    refname)) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}

		if (strncmp(refname, "refs/heads/", 11) == 0)
			refname += 11;

		if ((asprintf(&head_row, heads_row, age, refname,
		    head_navs_disp)) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}

		error = buf_puts(&newsize, diffbuf, head_row);

		free(head_navs_disp);
		free(head_row);
	}

	if (buf_len(diffbuf) > 0) {
		error = buf_putc(diffbuf, '\0');
		heads = strdup(buf_get(diffbuf));
	}
done:
	buf_free(diffbuf);
	got_ref_list_free(&refs);
	if (repo)
		got_repo_close(repo);
	if (error)
		return NULL;
	else
		return heads;
}

static char *
gw_get_got_link(struct trans *gw_trans)
{
	char *link;

	if ((asprintf(&link, got_link, gw_trans->gw_conf->got_logo_url,
	    gw_trans->gw_conf->got_logo)) == -1)
		return NULL;

	return link;
}

static char *
gw_get_site_link(struct trans *gw_trans)
{
	char *link, *repo = "", *action = "";

	if (gw_trans->repo_name != NULL)
		if ((asprintf(&repo, " / <a href='?path=%s&action=summary'>%s" \
		    "</a>", gw_trans->repo_name, gw_trans->repo_name)) == -1)
			return NULL;

	if (gw_trans->action_name != NULL)
		if ((asprintf(&action, " / %s", gw_trans->action_name)) == -1)
			return NULL;

	if ((asprintf(&link, site_link, GOTWEB,
	    gw_trans->gw_conf->got_site_link, repo, action)) == -1)
		return NULL;

	return link;
}

static char *
gw_html_escape(const char *html)
{
	char *escaped_str = NULL, *buf;
	char c[1];
	size_t sz, i, buff_sz = 2048;

	if ((buf = calloc(buff_sz, sizeof(char *))) == NULL)
		return NULL;

	if (html == NULL)
		return NULL;
	else
		if ((sz = strlen(html)) == 0)
			return NULL;

	/* only work with buff_sz */
	if (buff_sz < sz)
		sz = buff_sz;

	for (i = 0; i < sz; i++) {
		c[0] = html[i];
		switch (c[0]) {
		case ('>'):
			strcat(buf, "&gt;");
			break;
		case ('&'):
			strcat(buf, "&amp;");
			break;
		case ('<'):
			strcat(buf, "&lt;");
			break;
		case ('"'):
			strcat(buf, "&quot;");
			break;
		case ('\''):
			strcat(buf, "&apos;");
			break;
		case ('\n'):
			strcat(buf, "<br />");
		case ('|'):
			strcat(buf, " ");
		default:
			strcat(buf, &c[0]);
			break;
		}
	}
	asprintf(&escaped_str, "%s", buf);
	free(buf);
	return escaped_str;
}

int
main()
{
	const struct got_error *error = NULL;
	struct trans *gw_trans;
	struct gw_dir *dir = NULL, *tdir;
	const char *page = "index";
	int gw_malloc = 1;

	if ((gw_trans = malloc(sizeof(struct trans))) == NULL)
		errx(1, "malloc");

	if ((gw_trans->gw_req = malloc(sizeof(struct kreq))) == NULL)
		errx(1, "malloc");

	if ((gw_trans->gw_html_req = malloc(sizeof(struct khtmlreq))) == NULL)
		errx(1, "malloc");

	if ((gw_trans->gw_tmpl = malloc(sizeof(struct ktemplate))) == NULL)
		errx(1, "malloc");

	if (KCGI_OK != khttp_parse(gw_trans->gw_req, gw_keys, KEY__MAX,
	    &page, 1, 0))
		errx(1, "khttp_parse");

	if ((gw_trans->gw_conf =
	    malloc(sizeof(struct gotweb_conf))) == NULL) {
		gw_malloc = 0;
		error = got_error_from_errno("malloc");
		goto err;
	}

	if (pledge("stdio rpath proc exec sendfd unveil", NULL) == -1) {
		error = got_error_from_errno("pledge");
		goto err;
	}

	TAILQ_INIT(&gw_trans->gw_dirs);

	gw_trans->page = 0;
	gw_trans->repos_total = 0;
	gw_trans->repo_path = NULL;
	gw_trans->commit = NULL;
	gw_trans->headref = strdup(GOT_REF_HEAD);
	gw_trans->mime = KMIME_TEXT_HTML;
	gw_trans->gw_tmpl->key = templs;
	gw_trans->gw_tmpl->keysz = TEMPL__MAX;
	gw_trans->gw_tmpl->arg = gw_trans;
	gw_trans->gw_tmpl->cb = gw_template;
	error = parse_conf(GOTWEB_CONF, gw_trans->gw_conf);

err:
	if (error) {
		gw_trans->mime = KMIME_TEXT_PLAIN;
		gw_trans->action = GW_ERR;
		gw_display_index(gw_trans, error);
		goto done;
	}

	error = gw_parse_querystring(gw_trans);
	if (error)
		goto err;

	gw_display_index(gw_trans, error);

done:
	if (gw_malloc) {
		free(gw_trans->gw_conf->got_repos_path);
		free(gw_trans->gw_conf->got_www_path);
		free(gw_trans->gw_conf->got_site_name);
		free(gw_trans->gw_conf->got_site_owner);
		free(gw_trans->gw_conf->got_site_link);
		free(gw_trans->gw_conf->got_logo);
		free(gw_trans->gw_conf->got_logo_url);
		free(gw_trans->gw_conf);
		free(gw_trans->commit);
		free(gw_trans->repo_path);
		free(gw_trans->repo_name);
		free(gw_trans->repo_file);
		free(gw_trans->action_name);
		free(gw_trans->headref);

		TAILQ_FOREACH_SAFE(dir, &gw_trans->gw_dirs, entry, tdir) {
			free(dir->name);
			free(dir->description);
			free(dir->age);
			free(dir->url);
			free(dir->path);
			free(dir);
		}

	}

	khttp_free(gw_trans->gw_req);
	return EXIT_SUCCESS;
}
