/*
 * Copyright (c) 2019 Tracey Emery <tracey@traceyemery.net>
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

struct buf {
	/* buffer handle, buffer size, and data length */
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
};

static struct gw_dir		*gw_init_gw_dir(char *);

static char			*gw_get_repo_description(struct trans *,
				    char *);
static char			*gw_get_repo_owner(struct trans *,
				    char *);
static char			*gw_get_time_str(time_t, int);
static char			*gw_get_repo_age(struct trans *,
				    char *, char *, int);
static char			*gw_get_repo_shortlog(struct trans *,
				    const char *);
static char			*gw_get_repo_tags(struct trans *);
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
static const struct got_error*	 gw_load_got_paths(struct trans *);
static const struct got_error*	 gw_load_got_path(struct trans *,
				    struct gw_dir *);
static const struct got_error*	 gw_parse_querystring(struct trans *);
static const struct got_error*	 match_logmsg(int *, struct got_object_id *,
				    struct got_commit_object *, regex_t *);

static const struct got_error*	 gw_blame(struct trans *);
static const struct got_error*	 gw_blob(struct trans *);
static const struct got_error*	 gw_blob_diff(struct trans *);
static const struct got_error*	 gw_commit(struct trans *);
static const struct got_error*	 gw_commit_diff(struct trans *);
static const struct got_error*	 gw_history(struct trans *);
static const struct got_error*	 gw_index(struct trans *);
static const struct got_error*	 gw_log(struct trans *);
static const struct got_error*	 gw_raw(struct trans *);
static const struct got_error*	 gw_shortlog(struct trans *);
static const struct got_error*	 gw_snapshot(struct trans *);
static const struct got_error*	 gw_summary(struct trans *);
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
	GW_SHORTLOG,
	GW_SNAPSHOT,
	GW_SUMMARY,
	GW_TREE
};

static struct gw_query_action gw_query_funcs[] = {
	{ GW_BLAME,	 "blame",	gw_blame,	"gw_tmpl/index.tmpl" },
	{ GW_BLOB,	 "blob",	gw_blob,	"gw_tmpl/index.tmpl" },
	{ GW_BLOBDIFF,	 "blobdiff",	gw_blob_diff,	"gw_tmpl/index.tmpl" },
	{ GW_COMMIT,	 "commit",	gw_commit,	"gw_tmpl/index.tmpl" },
	{ GW_COMMITDIFF, "commit_diff",	gw_commit_diff,	"gw_tmpl/index.tmpl" },
	{ GW_ERR,	 NULL,		NULL,		"gw_tmpl/index.tmpl" },
	{ GW_HISTORY,	 "history",	gw_history,	"gw_tmpl/index.tmpl" },
	{ GW_INDEX,	 "index",	gw_index,	"gw_tmpl/index.tmpl" },
	{ GW_LOG,	 "log",		gw_log,		"gw_tmpl/index.tmpl" },
	{ GW_RAW,	 "raw",		gw_raw,		"gw_tmpl/index.tmpl" },
	{ GW_SHORTLOG,	 "shortlog",	gw_shortlog,	"gw_tmpl/index.tmpl" },
	{ GW_SNAPSHOT,	 "snapshot",	gw_snapshot,	"gw_tmpl/index.tmpl" },
	{ GW_SUMMARY,	 "summary",	gw_summary,	"gw_tmpl/index.tmpl" },
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
gw_blob_diff(struct trans *gw_trans)
{
	const struct got_error *error = NULL;

	return error;
}

static const struct got_error *
gw_commit(struct trans *gw_trans)
{
	const struct got_error *error = NULL;

	return error;
}

static const struct got_error *
gw_commit_diff(struct trans *gw_trans)
{
	const struct got_error *error = NULL;

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

	return error;
}

static const struct got_error *
gw_raw(struct trans *gw_trans)
{
	const struct got_error *error = NULL;

	return error;
}

static const struct got_error *
gw_shortlog(struct trans *gw_trans)
{
	const struct got_error *error = NULL;

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
	     *cloneurl_html, *shortlog, *tags, *heads, *shortlog_html,
	     *tags_html, *heads_html, *age;

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

	shortlog = gw_get_repo_shortlog(gw_trans, NULL);
	tags = gw_get_repo_tags(gw_trans);
	heads = gw_get_repo_heads(gw_trans);

	if (shortlog != NULL && strcmp(shortlog, "") != 0) {
		if ((asprintf(&shortlog_html, summary_shortlog,
		    shortlog)) == -1)
			return got_error_from_errno("asprintf");
		khttp_puts(gw_trans->gw_req, shortlog_html);
		free(shortlog_html);
		free(shortlog);
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
gw_tree(struct trans *gw_trans)
{
	const struct got_error *error = NULL;

	return error;
}

static const struct got_error *
gw_load_got_path(struct trans *gw_trans, struct gw_dir *gw_dir)
{
	const struct got_error *error = NULL;
	DIR *dt;
	char *dir_test;
	bool opened = false;

	if ((asprintf(&dir_test, "%s/%s/%s",
	    gw_trans->gw_conf->got_repos_path, gw_dir->name,
	    GOTWEB_GIT_DIR)) == -1)
		return got_error_from_errno("asprintf");

	dt = opendir(dir_test);
	if (dt == NULL) {
		free(dir_test);
	} else {
		gw_dir->path = strdup(dir_test);
		opened = true;
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
		opened = true;
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
	char datebuf[BUFFER_SIZE];

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
	time_t committer_time = 0, cmp_time = 0;
	char *repo_age = NULL;

	if (repo_ref == NULL)
		return NULL;

	SIMPLEQ_INIT(&refs);
	if (gw_trans->gw_conf->got_show_repo_age == false) {
		asprintf(&repo_age, "");
		return repo_age;
	}
	error = got_repo_open(&repo, dir, NULL);
	if (error != NULL)
		goto err;

	error = got_ref_list(&refs, repo, repo_ref, got_ref_cmp_by_name,
	    NULL);
	if (error != NULL)
		goto err;

	const char *refname;
	SIMPLEQ_FOREACH(re, &refs, entry) {
		refname = got_ref_get_name(re->ref);
		error = got_ref_open(&head_ref, repo, refname, 0);
		if (error != NULL)
			goto err;

		error = got_ref_resolve(&id, repo, head_ref);
		got_ref_close(head_ref);
		if (error != NULL)
			goto err;

		/*  here is what breaks tags, so adjust */
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

	if ((buf = calloc(BUFFER_SIZE, sizeof(char *))) == NULL)
		goto err;

	while ((fgets(buf, BUFFER_SIZE, f)) != NULL) {
		if ((pos = strstr(buf, gotweb)) != NULL)
			break;

		if ((pos = strstr(buf, gitweb)) != NULL)
			break;
	}

	if (pos == NULL)
		goto err;

	do {
		fgets(buf, BUFFER_SIZE, f);
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
gw_get_repo_shortlog(struct trans *gw_trans, const char *search_pattern)
{
	const struct got_error *error;
	struct got_repository *repo = NULL;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;
	struct got_commit_object *commit = NULL;
	struct got_object_id *id = NULL;
	struct got_commit_graph *graph = NULL;
	char *start_commit = NULL, *shortlog = NULL, *id_str = NULL,
	     *path = NULL, *in_repo_path = NULL, *commit_row = NULL,
	     *commit_age = NULL, *commit_author = NULL, *commit_log = NULL,
	     *shortlog_navs_html = NULL;
	regex_t regex;
	int have_match, limit = D_MAXSLCOMMDISP;
	size_t newsize;
	struct buf *diffbuf;
	time_t committer_time;

	if (search_pattern &&
	    regcomp(&regex, search_pattern, REG_EXTENDED | REG_NOSUB |
	    REG_NEWLINE))
		return NULL;

	SIMPLEQ_INIT(&refs);

	error = got_repo_open(&repo, gw_trans->repo_path, NULL);
	if (error != NULL)
		goto done;

	error = buf_alloc(&diffbuf, BUFFER_SIZE);
	if (error != NULL)
		goto done;

	if (start_commit == NULL) {
		struct got_reference *head_ref;
		error = got_ref_open(&head_ref, repo, GOT_REF_HEAD, 0);
		if (error != NULL)
			return NULL;
		error = got_ref_resolve(&id, repo, head_ref);
		got_ref_close(head_ref);
		if (error != NULL)
			return NULL;
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
				return NULL;
		}
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

	error = got_commit_graph_open(&graph, id, path, 0, repo);
	if (error)
		goto done;

	error = got_commit_graph_iter_start(graph, id, repo, NULL, NULL);
	if (error)
		goto done;

	for (;;) {
		struct got_commit_object *commit_disp;

		error = got_commit_graph_iter_next(&id, graph);
		if (error) {
			if (error->code == GOT_ERR_ITER_COMPLETED) {
				error = NULL;
				break;
			}
			if (error->code != GOT_ERR_ITER_NEED_MORE)
				break;
			error = got_commit_graph_fetch_commits(graph, 1, repo,
			    NULL, NULL);
			if (error)
				break;
			else
				continue;
		}
		if (id == NULL)
			break;

		error = got_object_open_as_commit(&commit_disp, repo, id);
		if (error)
			break;

		if (search_pattern) {
			error = match_logmsg(&have_match, id, commit_disp,
			    &regex);
			if (error) {
				got_object_commit_close(commit_disp);
				break;
			}
			if (have_match == 0) {
				got_object_commit_close(commit_disp);
				continue;
			}
		}

		SIMPLEQ_FOREACH(re, &refs, entry) {
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
			    got_object_tag_get_object_id(tag) : re->id, id);
			if (tag)
				got_object_tag_close(tag);
			if (cmp != 0)
				continue;
		}

		got_ref_list_free(&refs);

		/* commit id */
		error = got_object_id_str(&id_str, id);
		if (error)
			break;

		committer_time =
		    got_object_commit_get_committer_time(commit_disp);
		asprintf(&commit_age, "%s", gw_get_time_str(committer_time,
		    TM_DIFF));
		asprintf(&commit_author, "%s",
		    got_object_commit_get_author(commit_disp));
		error = got_object_commit_get_logmsg(&commit_log, commit_disp);
		if (error)
			commit_log = strdup("");
		asprintf(&shortlog_navs_html, shortlog_navs,
		    gw_trans->repo_name, id_str, gw_trans->repo_name, id_str,
		    gw_trans->repo_name, id_str, gw_trans->repo_name, id_str);
		asprintf(&commit_row, shortlog_row, commit_age, commit_author,
		    commit_log, shortlog_navs_html);
		error = buf_append(&newsize, diffbuf, commit_row,
		    strlen(commit_row));

		free(commit_age);
		free(commit_author);
		free(commit_log);
		free(shortlog_navs_html);
		free(commit_row);
		free(id_str);
		commit_age = NULL;
		commit_author = NULL;
		commit_log = NULL;
		shortlog_navs_html = NULL;
		commit_row = NULL;
		id_str = NULL;

		got_object_commit_close(commit_disp);
		if (error || (limit && --limit == 0))
			break;
	}
	shortlog = strdup(diffbuf->cb_buf);
	got_object_commit_close(commit);

	free(path);
	free(id);
	buf_free(diffbuf);

	if (repo) {
		error = got_repo_close(repo);
		if (error != NULL)
			return NULL;
	}

	if (search_pattern)
		regfree(&regex);
	return shortlog;
done:
	if (repo)
		got_repo_close(repo);
	got_ref_list_free(&refs);

	if (search_pattern)
		regfree(&regex);
	got_commit_graph_close(graph);
	return NULL;
}

static char *
gw_get_repo_tags(struct trans *gw_trans)
{
	char *tags = NULL;

	asprintf(&tags, tags_row, "30 min ago", "1.0.0", "tag 1.0.0", tags_navs);
	return tags;
}

static char *
gw_get_repo_heads(struct trans *gw_trans)
{
	char *heads = NULL;

	asprintf(&heads, heads_row, "30 min ago", "master", heads_navs);
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
	size_t sz, i;

	if ((buf = calloc(BUFFER_SIZE, sizeof(char *))) == NULL)
		return NULL;

	if (html == NULL)
		return NULL;
	else
		if ((sz = strlen(html)) == 0)
			return NULL;

	/* only work with BUFFER_SIZE */
	if (BUFFER_SIZE < sz)
		sz = BUFFER_SIZE;

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
	struct trans *gw_trans;
	struct gw_dir *dir = NULL, *tdir;
	const char *page = "index";
	bool gw_malloc = true;

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
		gw_malloc = false;
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
