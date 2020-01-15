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

#include "gotweb.h"
#include "gotweb_ui.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

struct trans {
	TAILQ_HEAD(dirs, gw_dir) gw_dirs;
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
	TEMPL_DESCRIPTION,
	TEMPL_CONTENT,
	TEMPL_REPO_OWNER,
	TEMPL_REPO_AGE,
	TEMPL_CLONEURL,
	TEMPL__MAX
};

enum ref_tm {
	TM_DIFF,
	TM_LONG,
};

static const char *const templs[TEMPL__MAX] = {
	"head",
	"header",
	"sitepath",
	"siteowner",
	"title",
	"search",
	"description",
	"content",
	"repo_owner",
	"repo_age",
	"cloneurl",
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
static char			*gw_get_repo_age(struct trans *,
				    char *, char *, int);
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
	{ GW_SUMMARY,	 "summary",	gw_summary,	"gw_tmpl/summary.tmpl" },
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
	struct gw_dir *dir = NULL;
	char *html, *navs, *next, *prev;
	unsigned int prev_disp = 0, next_disp = 1, dir_c = 0;

	error = gw_load_got_paths(gw_trans);
	if (error && error->code != GOT_ERR_OK)
		return error;

	khttp_puts(gw_trans->gw_req, index_projects_header);

	TAILQ_FOREACH(dir, &gw_trans->gw_dirs, entry)
		dir_c++;

	TAILQ_FOREACH(dir, &gw_trans->gw_dirs, entry) {
		if (gw_trans->page > 0 && (gw_trans->page *
		    gw_trans->gw_conf->got_max_repos_display) > prev_disp) {
			prev_disp++;
			continue;
		}

		prev_disp++;
		if((asprintf(&navs, index_navs, dir->name, dir->name, dir->name,
		    dir->name)) == -1)
			return got_error_from_errno("asprintf");

		if ((asprintf(&html, index_projects, dir->name, dir->name,
		    dir->description, dir->owner, dir->age, navs)) == -1)
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

		khttp_puts(gw_trans->gw_req, summary_shortlog);
		khttp_puts(gw_trans->gw_req, summary_tags);
		khttp_puts(gw_trans->gw_req, summary_heads);
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

	if (pledge("stdio rpath proc exec sendfd unveil", NULL) == -1) {
		error = got_error_from_errno("pledge");
		return error;
	}

	error = apply_unveil(gw_trans->gw_conf->got_repos_path, NULL);
	if (error)
		return error;

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
	char *description, *description_h;
	char *repo_owner, *repo_owner_h;
	char *repo_age, *repo_age_h;
	char *cloneurl, *cloneurl_h;

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
	case(TEMPL_DESCRIPTION):
		if (gw_trans->gw_conf->got_show_repo_description) {
			description = gw_html_escape(
			    gw_get_repo_description(gw_trans,
			    gw_trans->repo_path));
			if (description != NULL &&
			    (strcmp(description, "") != 0)) {
				if ((asprintf(&description_h,
				    summary_description, description)) == -1)
					return 0;

				khttp_puts(gw_trans->gw_req, description_h);
				free(description);
				free(description_h);
			}
		}
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
	case(TEMPL_REPO_OWNER):
		if (gw_trans->gw_conf->got_show_repo_owner) {
			repo_owner = gw_html_escape(gw_get_repo_owner(gw_trans,
			    gw_trans->repo_path));
			if ((asprintf(&repo_owner_h, summary_repo_owner,
			    repo_owner)) == -1)
				return 0;

			if (repo_owner != NULL &&
			    (strcmp(repo_owner, "") != 0)) {
				khttp_puts(gw_trans->gw_req, repo_owner_h);
			}

			free(repo_owner_h);
		}
		break;
	case(TEMPL_REPO_AGE):
		if (gw_trans->gw_conf->got_show_repo_age) {
			repo_age = gw_get_repo_age(gw_trans,
			    gw_trans->repo_path, "refs/heads", TM_LONG);
			if (repo_age != NULL) {
				if ((asprintf(&repo_age_h, summary_last_change,
				    repo_age)) == -1)
				return 0;
				khttp_puts(gw_trans->gw_req, repo_age_h);
				free(repo_age);
				free(repo_age_h);
			}
		}
		break;
	case(TEMPL_CLONEURL):
		if (gw_trans->gw_conf->got_show_repo_cloneurl) {
			cloneurl = gw_html_escape(gw_get_clone_url(gw_trans,
			    gw_trans->repo_path));
			if (cloneurl != NULL) {
				if ((asprintf(&cloneurl_h,
				    summary_cloneurl, cloneurl)) == -1)
					return 0;

				khttp_puts(gw_trans->gw_req, cloneurl_h);
				free(cloneurl);
				free(cloneurl_h);
			}

		}
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
gw_get_repo_age(struct trans *gw_trans, char *dir, char *repo_ref, int ref_tm)
{
	const struct got_error *error = NULL;
	struct got_object_id *id = NULL;
	struct got_repository *repo = NULL;
	struct got_commit_object *commit = NULL;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;
	struct got_reference *head_ref;
	struct tm tm;
	time_t committer_time = 0, cmp_time = 0, diff_time;
	char *repo_age = NULL, *years = "years ago", *months = "months ago";
	char *weeks = "weeks ago", *days = "days ago", *hours = "hours ago";
	char *minutes = "minutes ago", *seconds = "seconds ago";
	char *now = "right now";
	char datebuf[BUFFER_SIZE];

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

	if (cmp_time != 0)
		committer_time = cmp_time;

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
		if (cmp_time != 0) {
			if (gmtime_r(&committer_time, &tm) == NULL)
				return NULL;
			if (strftime(datebuf, sizeof(datebuf),
			    "%G-%m-%d %H:%M:%S (%z)",
			    &tm) >= sizeof(datebuf))
				return NULL;

			if ((asprintf(&repo_age, "%s", datebuf)) == -1)
				return NULL;
		} else {
			if ((asprintf(&repo_age, "")) == -1)
				return NULL;
		}
		break;
	}

noref:
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
