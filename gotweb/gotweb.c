/*
 * Copyright (c) 2019, 2020 Tracey Emery <tracey@traceyemery.net>
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

struct gw_trans {
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
	char			*repo_folder;
	char			*action_name;
	char			*headref;
	unsigned int		 action;
	unsigned int		 page;
	unsigned int		 repos_total;
	enum kmime		 mime;
};

enum gw_key {
	KEY_ACTION,
	KEY_COMMIT_ID,
	KEY_FILE,
	KEY_FOLDER,
	KEY_HEADREF,
	KEY_PAGE,
	KEY_PATH,
	KEY__ZMAX
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

enum gw_tmpl {
	TEMPL_HEAD,
	TEMPL_HEADER,
	TEMPL_SITEPATH,
	TEMPL_SITEOWNER,
	TEMPL_TITLE,
	TEMPL_SEARCH,
	TEMPL_CONTENT,
	TEMPL__MAX
};

enum gw_ref_tm {
	TM_DIFF,
	TM_LONG,
};

enum gw_logs {
	LOGBRIEF,
	LOGCOMMIT,
	LOGFULL,
	LOGTREE,
	LOGDIFF,
	LOGBLAME,
	LOGTAG,
};

enum gw_tags {
	TAGBRIEF,
	TAGFULL,
};

static const char *const gw_templs[TEMPL__MAX] = {
	"head",
	"header",
	"sitepath",
	"siteowner",
	"title",
	"search",
	"content",
};

static const struct kvalid gw_keys[KEY__ZMAX] = {
	{ kvalid_stringne,	"action" },
	{ kvalid_stringne,	"commit" },
	{ kvalid_stringne,	"file" },
	{ kvalid_stringne,	"folder" },
	{ kvalid_stringne,	"headref" },
	{ kvalid_int,		"page" },
	{ kvalid_stringne,	"path" },
};

int				 gw_get_repo_log_count(struct gw_trans *,
				    char *);

static struct gw_dir		*gw_init_gw_dir(char *);

static char			*gw_get_repo_description(struct gw_trans *,
				    char *);
static char			*gw_get_repo_owner(struct gw_trans *,
				    char *);
static char			*gw_get_time_str(time_t, int);
static char			*gw_get_repo_age(struct gw_trans *,
				    char *, char *, int);
static char			*gw_get_repo_log(struct gw_trans *,
				    const char *, char *, int, int);
static char			*gw_get_file_blame(struct gw_trans *, char *);
static char			*gw_get_repo_tree(struct gw_trans *, char *);
static char			*gw_get_repo_diff(struct gw_trans *, char *,
				    char *);
static char			*gw_get_repo_tags(struct gw_trans *, int, int);
static char			*gw_get_repo_heads(struct gw_trans *);
static char			*gw_get_clone_url(struct gw_trans *, char *);
static char			*gw_get_got_link(struct gw_trans *);
static char			*gw_get_site_link(struct gw_trans *);
static char			*gw_html_escape(const char *);
static char			*gw_colordiff_line(char *);

static void			 gw_display_open(struct gw_trans *, enum khttp,
				    enum kmime);
static void			 gw_display_index(struct gw_trans *,
				    const struct got_error *);

static int			 gw_template(size_t, void *);

static const struct got_error*	 gw_apply_unveil(const char *, const char *);
static const struct got_error*	 gw_blame_cb(void *, int, int,
				    struct got_object_id *);
static const struct got_error*	 gw_load_got_paths(struct gw_trans *);
static const struct got_error*	 gw_load_got_path(struct gw_trans *,
				    struct gw_dir *);
static const struct got_error*	 gw_parse_querystring(struct gw_trans *);
static const struct got_error*	 match_logmsg(int *, struct got_object_id *,
				    struct got_commit_object *, regex_t *);

static const struct got_error*	 gw_blame(struct gw_trans *);
static const struct got_error*	 gw_commit(struct gw_trans *);
static const struct got_error*	 gw_commitdiff(struct gw_trans *);
static const struct got_error*	 gw_index(struct gw_trans *);
static const struct got_error*	 gw_log(struct gw_trans *);
static const struct got_error*	 gw_raw(struct gw_trans *);
static const struct got_error*	 gw_logbriefs(struct gw_trans *);
static const struct got_error*	 gw_summary(struct gw_trans *);
static const struct got_error*	 gw_tag(struct gw_trans *);
static const struct got_error*	 gw_tree(struct gw_trans *);

struct gw_query_action {
	unsigned int		 func_id;
	const char		*func_name;
	const struct got_error	*(*func_main)(struct gw_trans *);
	char			*template;
};

enum gw_query_actions {
	GW_BLAME,
	GW_COMMIT,
	GW_COMMITDIFF,
	GW_ERR,
	GW_INDEX,
	GW_LOG,
	GW_RAW,
	GW_LOGBRIEFS,
	GW_SUMMARY,
	GW_TAG,
	GW_TREE,
};

static struct gw_query_action gw_query_funcs[] = {
	{ GW_BLAME,	 "blame",	gw_blame,	"gw_tmpl/index.tmpl" },
	{ GW_COMMIT,	 "commit",	gw_commit,	"gw_tmpl/index.tmpl" },
	{ GW_COMMITDIFF, "commitdiff",	gw_commitdiff,	"gw_tmpl/index.tmpl" },
	{ GW_ERR,	 NULL,		NULL,		"gw_tmpl/index.tmpl" },
	{ GW_INDEX,	 "index",	gw_index,	"gw_tmpl/index.tmpl" },
	{ GW_LOG,	 "log",		gw_log,		"gw_tmpl/index.tmpl" },
	{ GW_RAW,	 "raw",		gw_raw,		"gw_tmpl/index.tmpl" },
	{ GW_LOGBRIEFS,	 "logbriefs",	gw_logbriefs,	"gw_tmpl/index.tmpl" },
	{ GW_SUMMARY,	 "summary",	gw_summary,	"gw_tmpl/index.tmpl" },
	{ GW_TAG,	 "tag",		gw_tag,		"gw_tmpl/index.tmpl" },
	{ GW_TREE,	 "tree",	gw_tree,	"gw_tmpl/index.tmpl" },
};

static const struct got_error *
gw_apply_unveil(const char *repo_path, const char *repo_file)
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

int
gw_get_repo_log_count(struct gw_trans *gw_trans, char *start_commit)
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
	if (error)
		return 0;

	SIMPLEQ_INIT(&refs);

	if (start_commit == NULL) {
		struct got_reference *head_ref;
		error = got_ref_open(&head_ref, repo, gw_trans->headref, 0);
		if (error)
			goto done;

		error = got_ref_resolve(&id, repo, head_ref);
		got_ref_close(head_ref);
		if (error)
			goto done;

		error = got_object_open_as_commit(&commit, repo, id);
	} else {
		struct got_reference *ref;
		error = got_ref_open(&ref, repo, start_commit, 0);
		if (error == NULL) {
			int obj_type;
			error = got_ref_resolve(&id, repo, ref);
			got_ref_close(ref);
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
			error = got_object_open_as_commit(&commit, repo, id);
			if (error)
				goto done;
		}
		if (commit == NULL) {
			error = got_repo_match_object_id_prefix(&id,
			    start_commit, GOT_OBJ_TYPE_COMMIT, repo);
			if (error)
				goto done;
		}
		error = got_repo_match_object_id_prefix(&id,
			    start_commit, GOT_OBJ_TYPE_COMMIT, repo);
			if (error)
				goto done;
	}

	error = got_object_open_as_commit(&commit, repo, id);
	if (error)
		goto done;

	error = got_repo_map_path(&in_repo_path, repo, gw_trans->repo_path, 1);
	if (error)
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
	free(in_repo_path);
	if (graph)
		got_commit_graph_close(graph);
	if (repo) {
		error = got_repo_close(repo);
		if (error)
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
gw_blame(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;

	char *log, *log_html;

	error = gw_apply_unveil(gw_trans->gw_dir->path, NULL);
	if (error)
		return error;

	log = gw_get_repo_log(gw_trans, NULL, gw_trans->commit, 1, LOGBLAME);

	if (log != NULL && strcmp(log, "") != 0) {
		if ((asprintf(&log_html, log_blame, log)) == -1)
			return got_error_from_errno("asprintf");
		khttp_puts(gw_trans->gw_req, log_html);
		free(log_html);
		free(log);
	}
	return error;
}

static const struct got_error *
gw_commit(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	char *log, *log_html;

	error = gw_apply_unveil(gw_trans->gw_dir->path, NULL);
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
gw_commitdiff(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	char *log, *log_html;

	error = gw_apply_unveil(gw_trans->gw_dir->path, NULL);
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
gw_index(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	struct gw_dir *gw_dir = NULL;
	char *html, *navs, *next, *prev;
	unsigned int prev_disp = 0, next_disp = 1, dir_c = 0;

	error = gw_apply_unveil(gw_trans->gw_conf->got_repos_path, NULL);
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
gw_log(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	char *log, *log_html;

	error = gw_apply_unveil(gw_trans->gw_dir->path, NULL);
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
gw_raw(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;

	return error;
}

static const struct got_error *
gw_logbriefs(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	char *log, *log_html;

	error = gw_apply_unveil(gw_trans->gw_dir->path, NULL);
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
gw_summary(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	char *description_html, *repo_owner_html, *repo_age_html,
	     *cloneurl_html, *log, *log_html, *tags, *heads, *tags_html,
	     *heads_html, *age;

	error = gw_apply_unveil(gw_trans->gw_dir->path, NULL);
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
gw_tag(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	char *log, *log_html;

	error = gw_apply_unveil(gw_trans->gw_dir->path, NULL);
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
gw_tree(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	char *log, *log_html;

	error = gw_apply_unveil(gw_trans->gw_dir->path, NULL);
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
gw_load_got_path(struct gw_trans *gw_trans, struct gw_dir *gw_dir)
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
gw_load_got_paths(struct gw_trans *gw_trans)
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
gw_parse_querystring(struct gw_trans *gw_trans)
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

 		if ((p = gw_trans->gw_req->fieldmap[KEY_COMMIT_ID]))
			if ((asprintf(&gw_trans->commit, "%s",
			    p->parsed.s)) == -1)
				return got_error_from_errno("asprintf");

		if ((p = gw_trans->gw_req->fieldmap[KEY_FILE]))
			if ((asprintf(&gw_trans->repo_file, "%s",
			    p->parsed.s)) == -1)
				return got_error_from_errno("asprintf");

		if ((p = gw_trans->gw_req->fieldmap[KEY_FOLDER]))
			if ((asprintf(&gw_trans->repo_folder, "%s",
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
gw_display_open(struct gw_trans *gw_trans, enum khttp code, enum kmime mime)
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
gw_display_index(struct gw_trans *gw_trans, const struct got_error *err)
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
	struct gw_trans *gw_trans = arg;
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
gw_get_repo_description(struct gw_trans *gw_trans, char *dir)
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
gw_get_repo_age(struct gw_trans *gw_trans, char *dir, char *repo_ref,
    int ref_tm)
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
	if (error)
		goto err;

	if (is_head)
		error = got_ref_list(&refs, repo, "refs/heads",
		    got_ref_cmp_by_name, NULL);
	else
		error = got_ref_list(&refs, repo, repo_ref,
		    got_ref_cmp_by_name, NULL);
	if (error)
		goto err;

	SIMPLEQ_FOREACH(re, &refs, entry) {
		if (is_head)
			refname = strdup(repo_ref);
		else
			refname = got_ref_get_name(re->ref);
		error = got_ref_open(&head_ref, repo, refname, 0);
		if (error)
			goto err;

		error = got_ref_resolve(&id, repo, head_ref);
		got_ref_close(head_ref);
		if (error)
			goto err;

		error = got_object_open_as_commit(&commit, repo, id);
		if (error)
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
gw_get_repo_diff(struct gw_trans *gw_trans, char *id_str1, char *id_str2)
{
	const struct got_error *error;
	FILE *f = NULL;
	struct got_object_id *id1 = NULL, *id2 = NULL;
	struct got_repository *repo = NULL;
	struct buf *diffbuf = NULL;
	char *label1 = NULL, *label2 = NULL, *diff_html = NULL, *buf = NULL,
	     *buf_color = NULL;
	int type1, type2;
	size_t newsize;

	f = got_opentemp();
	if (f == NULL)
		return NULL;

	error = buf_alloc(&diffbuf, 0);
	if (error)
		return NULL;

	error = got_repo_open(&repo, gw_trans->repo_path, NULL);
	if (error)
		goto done;

	error = got_repo_match_object_id(&id1, &label1, id_str1,
	    GOT_OBJ_TYPE_ANY, 1, repo);
	if (error)
		goto done;

	if (id_str2) {
		error = got_repo_match_object_id(&id2, &label2, id_str2,
		    GOT_OBJ_TYPE_ANY, 1, repo);
		if (error)
			goto done;

		error = got_object_get_type(&type2, repo, id2);
		if (error)
			goto done;
	}

	error = got_object_get_type(&type1, repo, id1);
	if (error)
		goto done;

	if (id_str2 && type1 != type2) {
		error = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	switch (type1) {
	case GOT_OBJ_TYPE_BLOB:
		error = got_diff_objects_as_blobs(id2, id1, NULL, NULL, 3, 0,
		    repo, f);
		break;
	case GOT_OBJ_TYPE_TREE:
		error = got_diff_objects_as_trees(id2, id1, "", "", 3, 0, repo,
		    f);
		break;
	case GOT_OBJ_TYPE_COMMIT:
		error = got_diff_objects_as_commits(id2, id1, 3, 0, repo, f);
		break;
	default:
		error = got_error(GOT_ERR_OBJ_TYPE);
	}

	if ((buf = calloc(128, sizeof(char *))) == NULL)
		goto done;

	fseek(f, 0, SEEK_SET);

	while ((fgets(buf, 128, f)) != NULL) {
		buf_color = gw_colordiff_line(buf);
		error = buf_puts(&newsize, diffbuf, buf_color);
		if (error)
			return NULL;

		error = buf_puts(&newsize, diffbuf, div_end);
		if (error)
			return NULL;
	}

	if (buf_len(diffbuf) > 0) {
		error = buf_putc(diffbuf, '\0');
		diff_html = strdup(buf_get(diffbuf));
	}
done:
	fclose(f);
	free(buf_color);
	free(buf);
	free(diffbuf);
	free(label1);
	free(label2);
	free(id1);
	free(id2);
	if (repo)
		got_repo_close(repo);

	if (error)
		return NULL;
	else
		return diff_html;
}

static char *
gw_get_repo_owner(struct gw_trans *gw_trans, char *dir)
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
gw_get_clone_url(struct gw_trans *gw_trans, char *dir)
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
gw_get_repo_log(struct gw_trans *gw_trans, const char *search_pattern,
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
	     *commit_tree_disp = NULL, *log_tag_html = NULL,
	     *log_blame_html = NULL;
	char *commit_log0, *newline;
	regex_t regex;
	int have_match, log_count = 0, has_parent = 1;
	size_t newsize;
	struct buf *diffbuf = NULL;
	time_t committer_time;

	if (gw_trans->action == GW_LOG || gw_trans->action == GW_LOGBRIEFS)
		log_count = gw_get_repo_log_count(gw_trans, start_commit);

	error = buf_alloc(&diffbuf, 0);
	if (error)
		return NULL;

	if (search_pattern &&
	    regcomp(&regex, search_pattern, REG_EXTENDED | REG_NOSUB |
	    REG_NEWLINE))
		return NULL;

	error = got_repo_open(&repo, gw_trans->repo_path, NULL);
	if (error)
		return NULL;

	SIMPLEQ_INIT(&refs);

	if (start_commit == NULL) {
		struct got_reference *head_ref;
		error = got_ref_open(&head_ref, repo, gw_trans->headref, 0);
		if (error)
			goto done;

		error = got_ref_resolve(&id1, repo, head_ref);
		got_ref_close(head_ref);
		if (error)
			goto done;

		error = got_object_open_as_commit(&commit, repo, id1);
	} else {
		struct got_reference *ref;
		error = got_ref_open(&ref, repo, start_commit, 0);
		if (error == NULL) {
			int obj_type;
			error = got_ref_resolve(&id1, repo, ref);
			got_ref_close(ref);
			if (error)
				goto done;
			error = got_object_get_type(&obj_type, repo, id1);
			if (error)
				goto done;
			if (obj_type == GOT_OBJ_TYPE_TAG) {
				struct got_tag_object *tag;
				error = got_object_open_as_tag(&tag, repo, id1);
				if (error)
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
			if (error)
				goto done;
		}
		if (commit == NULL) {
			error = got_repo_match_object_id_prefix(&id1,
			    start_commit, GOT_OBJ_TYPE_COMMIT, repo);
			if (error)
				goto done;
		}
		error = got_repo_match_object_id_prefix(&id1,
			    start_commit, GOT_OBJ_TYPE_COMMIT, repo);
	}

	if (error)
		goto done;

	error = got_repo_map_path(&in_repo_path, repo, gw_trans->repo_path, 1);
	if (error)
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
			} else {
				has_parent = 0;
				id_str2 = strdup("/dev/null");
			}
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
		case (LOGBLAME):
			log_blame_html = gw_get_file_blame(gw_trans,
			    start_commit);

			if ((asprintf(&commit_row, log_blame_row,
			    gw_html_escape(commit_log), log_blame_html)) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}

			free(log_blame_html);
			break;
		case (LOGTREE):
			log_tree_html = gw_get_repo_tree(gw_trans,
			    start_commit);

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

			if (has_parent)
				log_diff_html = gw_get_repo_diff(gw_trans,
				    commit_commit, commit_parent);
			else
				log_diff_html = gw_get_repo_diff(gw_trans,
				    commit_commit, NULL);

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
	free(in_repo_path);
	if (commit != NULL)
		got_object_commit_close(commit);
	if (search_pattern)
		regfree(&regex);
	if (graph)
		got_commit_graph_close(graph);
	if (repo) {
		error = got_repo_close(repo);
		if (error)
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
gw_get_repo_tags(struct gw_trans *gw_trans, int limit, int tag_type)
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
	if (error)
		return NULL;
	SIMPLEQ_INIT(&refs);

	error = got_repo_open(&repo, gw_trans->repo_path, NULL);
	if (error)
		goto done;

	error = got_ref_list(&refs, repo, "refs/tags", got_repo_cmp_tags, repo);
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

struct blame_line {
	int annotated;
	char *id_str;
	char *committer;
	char datebuf[11]; /* YYYY-MM-DD + NUL */
};

struct gw_blame_cb_args {
	struct blame_line *lines;
	int nlines;
	int nlines_prec;
	int lineno_cur;
	off_t *line_offsets;
	FILE *f;
	struct got_repository *repo;
	struct gw_trans *gw_trans;
	struct buf *blamebuf;
};

static const struct got_error *
gw_blame_cb(void *arg, int nlines, int lineno, struct got_object_id *id)
{
	const struct got_error *err = NULL;
	struct gw_blame_cb_args *a = arg;
	struct blame_line *bline;
	char *line = NULL;
	size_t linesize = 0, newsize;
	struct got_commit_object *commit = NULL;
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

	err = got_object_open_as_commit(&commit, a->repo, id);
	if (err)
		goto done;

	bline->committer = strdup(got_object_commit_get_committer(commit));
	if (bline->committer == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

	committer_time = got_object_commit_get_committer_time(commit);
	if (localtime_r(&committer_time, &tm) == NULL)
		return got_error_from_errno("localtime_r");
	if (strftime(bline->datebuf, sizeof(bline->datebuf), "%G-%m-%d",
	    &tm) >= sizeof(bline->datebuf)) {
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

	while (bline->annotated) {
		char *smallerthan, *at, *nl, *committer, *blame_row = NULL,
		     *line_escape = NULL;
		size_t len;

		if (getline(&line, &linesize, a->f) == -1) {
			if (ferror(a->f))
				err = got_error_from_errno("getline");
			break;
		}

		committer = bline->committer;
		smallerthan = strchr(committer, '<');
		if (smallerthan && smallerthan[1] != '\0')
			committer = smallerthan + 1;
		at = strchr(committer, '@');
		if (at)
			*at = '\0';
		len = strlen(committer);
		if (len >= 9)
			committer[8] = '\0';

		nl = strchr(line, '\n');
		if (nl)
			*nl = '\0';

		if (strcmp(line, "") != 0)
			line_escape = strdup(gw_html_escape(line));
		else
			line_escape = strdup("");

		asprintf(&blame_row, log_blame_line, a->nlines_prec,
		    a->lineno_cur, bline->id_str, bline->datebuf, committer,
		    line_escape);
		a->lineno_cur++;
		err = buf_puts(&newsize, a->blamebuf, blame_row);
		if (err)
			return err;

		bline = &a->lines[a->lineno_cur - 1];
		free(line_escape);
		free(blame_row);
	}
done:
	if (commit)
		got_object_commit_close(commit);
	free(line);
	return err;
}

static char*
gw_get_file_blame(struct gw_trans *gw_trans, char *commit_str)
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_object_id *obj_id = NULL;
	struct got_object_id *commit_id = NULL;
	struct got_blob_object *blob = NULL;
	char *blame_html = NULL, *path = NULL, *in_repo_path = NULL,
	     *folder = NULL;
	struct gw_blame_cb_args bca;
	int i, obj_type;
	size_t filesize;

	error = got_repo_open(&repo, gw_trans->repo_path, NULL);
	if (error)
		goto done;

	if (gw_trans->repo_folder != NULL) {
		if ((asprintf(&folder, "%s/", gw_trans->repo_folder)) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}
	} else
		folder = strdup("");

	if ((asprintf(&path, "%s%s", folder, gw_trans->repo_file)) == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}
	free(folder);

	error = got_repo_map_path(&in_repo_path, repo, path, 1);
	if (error)
		goto done;

	error = got_repo_match_object_id(&commit_id, NULL, commit_str,
	    GOT_OBJ_TYPE_COMMIT, 1, repo);
	if (error)
		goto done;

	error = got_object_id_by_path(&obj_id, repo, commit_id, in_repo_path);
	if (error)
		goto done;

	if (obj_id == NULL) {
		error = got_error(GOT_ERR_NO_OBJ);
		goto done;
	}

	error = got_object_get_type(&obj_type, repo, obj_id);
	if (error)
		goto done;

	if (obj_type != GOT_OBJ_TYPE_BLOB) {
		error = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	error = got_object_open_as_blob(&blob, repo, obj_id, 8192);
	if (error)
		goto done;

	error = buf_alloc(&bca.blamebuf, 0);
	if (error)
		goto done;

	bca.f = got_opentemp();
	if (bca.f == NULL) {
		error = got_error_from_errno("got_opentemp");
		goto done;
	}
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
	bca.gw_trans = gw_trans;

	error = got_blame(in_repo_path, commit_id, repo, gw_blame_cb, &bca,
	    NULL, NULL);
	if (buf_len(bca.blamebuf) > 0) {
		error = buf_putc(bca.blamebuf, '\0');
		blame_html = strdup(buf_get(bca.blamebuf));
	}
done:
	free(bca.blamebuf);
	free(in_repo_path);
	free(commit_id);
	free(obj_id);
	free(path);

	if (blob)
		error = got_object_blob_close(blob);
	if (repo)
		error = got_repo_close(repo);
	if (error)
		return NULL;
	if (bca.lines) {
		for (i = 0; i < bca.nlines; i++) {
			struct blame_line *bline = &bca.lines[i];
			free(bline->id_str);
			free(bline->committer);
		}
		free(bca.lines);
	}
	free(bca.line_offsets);
	if (bca.f && fclose(bca.f) == EOF && error == NULL)
		error = got_error_from_errno("fclose");
	if (error)
		return NULL;
	else
		return blame_html;
}

static char*
gw_get_repo_tree(struct gw_trans *gw_trans, char *commit_str)
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_object_id *tree_id = NULL, *commit_id = NULL;
	struct got_tree_object *tree = NULL;
	struct buf *diffbuf = NULL;
	size_t newsize;
	char *tree_html = NULL, *path = NULL, *in_repo_path = NULL,
	    *tree_row = NULL, *id_str;
	int nentries, i;

	error = buf_alloc(&diffbuf, 0);
	if (error)
		return NULL;

	error = got_repo_open(&repo, gw_trans->repo_path, NULL);
	if (error)
		goto done;

	error = got_repo_map_path(&in_repo_path, repo, gw_trans->repo_path, 1);
	if (error)
		goto done;

	if (gw_trans->repo_folder != NULL)
		path = strdup(gw_trans->repo_folder);
	else if (in_repo_path) {
		free(path);
		path = in_repo_path;
	}

	if (commit_str == NULL) {
		struct got_reference *head_ref;
		error = got_ref_open(&head_ref, repo, gw_trans->headref, 0);
		if (error)
			goto done;

		error = got_ref_resolve(&commit_id, repo, head_ref);
		got_ref_close(head_ref);

	} else
		error = got_repo_match_object_id(&commit_id, NULL, commit_str,
		    GOT_OBJ_TYPE_COMMIT, 1, repo);
	if (error)
		goto done;

	error = got_object_id_by_path(&tree_id, repo, commit_id, path);
	if (error)
		goto done;

	error = got_object_open_as_tree(&tree, repo, tree_id);
	if (error)
		goto done;

	nentries = got_object_tree_get_nentries(tree);

	for (i = 0; i < nentries; i++) {
		struct got_tree_entry *te;
		const char *modestr = "";
		char *id = NULL, *url_html = NULL;

		te = got_object_tree_get_entry(tree, i);

		error = got_object_id_str(&id_str, got_tree_entry_get_id(te));
		if (error)
			goto done;

		if ((asprintf(&id, "%s", id_str)) == -1) {
			error = got_error_from_errno("asprintf");
			free(id_str);
			goto done;
		}

		mode_t mode = got_tree_entry_get_mode(te);

		if (got_object_tree_entry_is_submodule(te))
			modestr = "$";
		else if (S_ISLNK(mode))
			modestr = "@";
		else if (S_ISDIR(mode))
			modestr = "/";
		else if (mode & S_IXUSR)
			modestr = "*";

		char *build_folder = NULL;
		if (S_ISDIR(got_tree_entry_get_mode(te))) {
			if (gw_trans->repo_folder != NULL) {
				if ((asprintf(&build_folder, "%s/%s",
				    gw_trans->repo_folder,
				    got_tree_entry_get_name(te))) == -1) {
					error =
					    got_error_from_errno("asprintf");
					goto done;
				}
			} else {
				if (asprintf(&build_folder, "%s",
				    got_tree_entry_get_name(te)) == -1)
					goto done;
			}

			if ((asprintf(&url_html, folder_html,
			    gw_trans->repo_name, gw_trans->action_name,
			    gw_trans->commit, build_folder,
			    got_tree_entry_get_name(te), modestr)) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}
		} else {
			if (gw_trans->repo_folder != NULL) {
				if ((asprintf(&build_folder, "%s",
				    gw_trans->repo_folder)) == -1) {
					error =
					    got_error_from_errno("asprintf");
					goto done;
				}
			} else
				build_folder = strdup("");

			if ((asprintf(&url_html, file_html, gw_trans->repo_name,
			    "blame", gw_trans->commit,
			    got_tree_entry_get_name(te), build_folder,
			    got_tree_entry_get_name(te), modestr)) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}
		}
		free(build_folder);

		if (error)
			goto done;

		if ((asprintf(&tree_row, trees_row, "", url_html)) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}
		error = buf_puts(&newsize, diffbuf, tree_row);
		if (error)
			goto done;

		free(id);
		free(id_str);
		free(url_html);
		free(tree_row);
	}

	if (buf_len(diffbuf) > 0) {
		error = buf_putc(diffbuf, '\0');
		tree_html = strdup(buf_get(diffbuf));
	}
done:
	if (tree)
		got_object_tree_close(tree);
	if (repo)
		got_repo_close(repo);

	free(in_repo_path);
	free(tree_id);
	free(diffbuf);
	if (error)
		return NULL;
	else
		return tree_html;
}

static char *
gw_get_repo_heads(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;
	char *heads, *head_row = NULL, *head_navs_disp = NULL, *age = NULL;
	struct buf *diffbuf = NULL;
	size_t newsize;

	error = buf_alloc(&diffbuf, 0);
	if (error)
		return NULL;

	error = got_repo_open(&repo, gw_trans->repo_path, NULL);
	if (error)
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
gw_get_got_link(struct gw_trans *gw_trans)
{
	char *link;

	if ((asprintf(&link, got_link, gw_trans->gw_conf->got_logo_url,
	    gw_trans->gw_conf->got_logo)) == -1)
		return NULL;

	return link;
}

static char *
gw_get_site_link(struct gw_trans *gw_trans)
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
gw_colordiff_line(char *buf)
{
	const struct got_error *error = NULL;
	char *colorized_line = NULL, *div_diff_line_div = NULL, *color = NULL;
	struct buf *diffbuf = NULL;
	size_t newsize;

	error = buf_alloc(&diffbuf, 0);
	if (error)
		return NULL;

	if (strncmp(buf, "-", 1) == 0)
		color = "diff_minus";
	if (strncmp(buf, "+", 1) == 0)
		color = "diff_plus";
	if (strncmp(buf, "@@", 2) == 0)
		color = "diff_chunk_header";
	if (strncmp(buf, "@@", 2) == 0)
		color = "diff_chunk_header";
	if (strncmp(buf, "commit +", 8) == 0)
		color = "diff_meta";
	if (strncmp(buf, "commit -", 8) == 0)
		color = "diff_meta";
	if (strncmp(buf, "blob +", 6) == 0)
		color = "diff_meta";
	if (strncmp(buf, "blob -", 6) == 0)
		color = "diff_meta";
	if (strncmp(buf, "file +", 6) == 0)
		color = "diff_meta";
	if (strncmp(buf, "file -", 6) == 0)
		color = "diff_meta";
	if (strncmp(buf, "from:", 5) == 0)
		color = "diff_author";
	if (strncmp(buf, "via:", 4) == 0)
		color = "diff_author";
	if (strncmp(buf, "date:", 5) == 0)
		color = "diff_date";

	if ((asprintf(&div_diff_line_div, div_diff_line, color)) == -1)
		return NULL;

	error = buf_puts(&newsize, diffbuf, div_diff_line_div);
	if (error)
		return NULL;

	error = buf_puts(&newsize, diffbuf, buf);
	if (error)
		return NULL;

	if (buf_len(diffbuf) > 0) {
		error = buf_putc(diffbuf, '\0');
		colorized_line = strdup(buf_get(diffbuf));
	}

	free(diffbuf);
	free(div_diff_line_div);
	return colorized_line;
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
	struct gw_trans *gw_trans;
	struct gw_dir *dir = NULL, *tdir;
	const char *page = "index";
	int gw_malloc = 1;

	if ((gw_trans = malloc(sizeof(struct gw_trans))) == NULL)
		errx(1, "malloc");

	if ((gw_trans->gw_req = malloc(sizeof(struct kreq))) == NULL)
		errx(1, "malloc");

	if ((gw_trans->gw_html_req = malloc(sizeof(struct khtmlreq))) == NULL)
		errx(1, "malloc");

	if ((gw_trans->gw_tmpl = malloc(sizeof(struct ktemplate))) == NULL)
		errx(1, "malloc");

	if (KCGI_OK != khttp_parse(gw_trans->gw_req, gw_keys, KEY__ZMAX,
	    &page, 1, 0))
		errx(1, "khttp_parse");

	if ((gw_trans->gw_conf =
	    malloc(sizeof(struct gotweb_conf))) == NULL) {
		gw_malloc = 0;
		error = got_error_from_errno("malloc");
		goto err;
	}

	if (pledge("stdio rpath wpath cpath proc exec sendfd unveil",
	    NULL) == -1) {
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
	gw_trans->gw_tmpl->key = gw_templs;
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
