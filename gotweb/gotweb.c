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

#include <ctype.h>
#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <regex.h>
#include <stdarg.h>
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
	TAILQ_HEAD(headers, gw_header)	 gw_headers;
	TAILQ_HEAD(dirs, gw_dir)	 gw_dirs;
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

struct gw_header {
	TAILQ_ENTRY(gw_header)		 entry;
	struct got_repository		*repo;
	struct got_reflist_head		 refs;
	struct got_commit_object	*commit;
	struct got_object_id		*id;
	char				*path;

	char			*refs_str;
	char			*commit_id; /* id_str1 */
	char			*parent_id; /* id_str2 */
	char			*tree_id;
	char			*author;
	char			*committer;
	char			*commit_msg;
	time_t			 committer_time;
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

enum gw_tmpl {
	TEMPL_CONTENT,
	TEMPL_HEAD,
	TEMPL_HEADER,
	TEMPL_SEARCH,
	TEMPL_SITEPATH,
	TEMPL_SITEOWNER,
	TEMPL_TITLE,
	TEMPL__MAX
};

enum gw_ref_tm {
	TM_DIFF,
	TM_LONG,
};

enum gw_tags {
	TAGBRIEF,
	TAGFULL,
};

static const char *const gw_templs[TEMPL__MAX] = {
	"content",
	"head",
	"header",
	"search",
	"sitepath",
	"siteowner",
	"title",
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

static struct gw_dir		*gw_init_gw_dir(char *);
static struct gw_header		*gw_init_header(void);

static const struct got_error	*gw_get_repo_description(char **, struct gw_trans *,
				    char *);
static const struct got_error	*gw_get_repo_owner(char **, struct gw_trans *,
				    char *);
static const struct got_error	*gw_get_time_str(char **, time_t, int);
static const struct got_error	*gw_get_repo_age(char **, struct gw_trans *,
				    char *, char *, int);
static const struct got_error	*gw_get_file_blame_blob(char **, struct gw_trans *);
static const struct got_error	*gw_get_file_read_blob(char **, struct gw_trans *);
static char			*gw_get_repo_tree(struct gw_trans *);
static char			*gw_get_diff(struct gw_trans *,
				    struct gw_header *);
static char			*gw_get_repo_tags(struct gw_trans *,
				    struct gw_header *, int, int);
static char			*gw_get_repo_heads(struct gw_trans *);
static const struct got_error	*gw_get_clone_url(char **, struct gw_trans *, char *);
static char			*gw_get_got_link(struct gw_trans *);
static char			*gw_get_site_link(struct gw_trans *);
static char			*gw_html_escape(const char *);
static char			*gw_colordiff_line(char *);

static char			*gw_gen_commit_header(char *, char*);
static char			*gw_gen_diff_header(char *, char*);
static char			*gw_gen_author_header(char *);
static char			*gw_gen_committer_header(char *);
static char			*gw_gen_commit_msg_header(char *);
static char			*gw_gen_tree_header(char *);

static void			 gw_free_headers(struct gw_header *);
static const struct got_error*	 gw_display_open(struct gw_trans *, enum khttp,
				    enum kmime);
static const struct got_error*	 gw_display_index(struct gw_trans *);
static void			 gw_display_error(struct gw_trans *,
				    const struct got_error *);

static int			 gw_template(size_t, void *);

static const struct got_error*	 gw_get_header(struct gw_trans *,
				    struct gw_header *, int);
static const struct got_error*	 gw_get_commits(struct gw_trans *,
				    struct gw_header *, int);
static const struct got_error*	 gw_get_commit(struct gw_trans *,
				    struct gw_header *);
static const struct got_error*	 gw_apply_unveil(const char *, const char *);
static const struct got_error*	 gw_blame_cb(void *, int, int,
				    struct got_object_id *);
static const struct got_error*	 gw_load_got_paths(struct gw_trans *);
static const struct got_error*	 gw_load_got_path(struct gw_trans *,
				    struct gw_dir *);
static const struct got_error*	 gw_parse_querystring(struct gw_trans *);

static const struct got_error*	 gw_blame(struct gw_trans *);
static const struct got_error*	 gw_blob(struct gw_trans *);
static const struct got_error*	 gw_diff(struct gw_trans *);
static const struct got_error*	 gw_index(struct gw_trans *);
static const struct got_error*	 gw_commits(struct gw_trans *);
static const struct got_error*	 gw_briefs(struct gw_trans *);
static const struct got_error*	 gw_summary(struct gw_trans *);
static const struct got_error*	 gw_tree(struct gw_trans *);
static const struct got_error*	 gw_tag(struct gw_trans *);

struct gw_query_action {
	unsigned int		 func_id;
	const char		*func_name;
	const struct got_error	*(*func_main)(struct gw_trans *);
	char			*template;
};

enum gw_query_actions {
	GW_BLAME,
	GW_BLOB,
	GW_BRIEFS,
	GW_COMMITS,
	GW_DIFF,
	GW_ERR,
	GW_INDEX,
	GW_SUMMARY,
	GW_TAG,
	GW_TREE,
};

static struct gw_query_action gw_query_funcs[] = {
	{ GW_BLAME,	"blame",	gw_blame,	"gw_tmpl/blame.tmpl" },
	{ GW_BLOB,	"blob",		NULL,		NULL },
	{ GW_BRIEFS,	"briefs",	gw_briefs,	"gw_tmpl/briefs.tmpl" },
	{ GW_COMMITS,	"commits",	gw_commits,	"gw_tmpl/commit.tmpl" },
	{ GW_DIFF,	"diff",		gw_diff,	"gw_tmpl/diff.tmpl" },
	{ GW_ERR,	 NULL,		NULL,		"gw_tmpl/err.tmpl" },
	{ GW_INDEX,	"index",	gw_index,	"gw_tmpl/index.tmpl" },
	{ GW_SUMMARY,	"summary",	gw_summary,	"gw_tmpl/summry.tmpl" },
	{ GW_TAG,	"tag",		gw_tag,		"gw_tmpl/tag.tmpl" },
	{ GW_TREE,	"tree",		gw_tree,	"gw_tmpl/tree.tmpl" },
};

static const struct got_error *
gw_kcgi_error(enum kcgi_err kerr)
{
	if (kerr == KCGI_OK)
		return NULL;

	if (kerr == KCGI_EXIT || kerr == KCGI_HUP)
		return got_error(GOT_ERR_CANCELLED);

	if (kerr == KCGI_ENOMEM)
		return got_error_set_errno(ENOMEM, kcgi_strerror(kerr));

	if (kerr == KCGI_ENFILE)
		return got_error_set_errno(ENFILE, kcgi_strerror(kerr));

	if (kerr == KCGI_EAGAIN)
		return got_error_set_errno(EAGAIN, kcgi_strerror(kerr));

	if (kerr == KCGI_FORM)
		return got_error_msg(GOT_ERR_IO, kcgi_strerror(kerr));

	return got_error_from_errno(kcgi_strerror(kerr));
}

static const struct got_error *
gw_apply_unveil(const char *repo_path, const char *repo_file)
{
	const struct got_error *err;

	if (repo_path && repo_file) {
		char *full_path;
		if (asprintf(&full_path, "%s/%s", repo_path, repo_file) == -1)
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
gw_empty_string(char **s)
{
	*s = strdup("");
	if (*s == NULL)
		return got_error_from_errno("strdup");
	return NULL;
}

static const struct got_error *
gw_blame(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	struct gw_header *header = NULL;
	char *blame = NULL, *blame_html = NULL, *blame_html_disp = NULL;
	char *age = NULL, *age_html = NULL;
	enum kcgi_err kerr;

	if (pledge("stdio rpath wpath cpath proc exec sendfd unveil",
	    NULL) == -1)
		return got_error_from_errno("pledge");

	if ((header = gw_init_header()) == NULL)
		return got_error_from_errno("malloc");

	error = gw_apply_unveil(gw_trans->gw_dir->path, NULL);
	if (error)
		goto done;

	error = gw_get_header(gw_trans, header, 1);
	if (error)
		goto done;

	error = gw_get_file_blame_blob(&blame_html, gw_trans);
	if (error)
		goto done;

	error = gw_get_time_str(&age, header->committer_time, TM_LONG);
	if (error)
		goto done;
	if (asprintf(&age_html, header_age_html, age ? age : "") == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}

	if (asprintf(&blame_html_disp, blame_header, age_html,
	    gw_gen_commit_msg_header(gw_html_escape(header->commit_msg)),
	    blame_html) == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}

	if (asprintf(&blame, blame_wrapper, blame_html_disp) == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}

	kerr = khttp_puts(gw_trans->gw_req, blame);
	if (kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
done:
	got_ref_list_free(&header->refs);
	gw_free_headers(header);
	free(blame_html_disp);
	free(blame_html);
	free(blame);
	return error;
}

static const struct got_error *
gw_blob(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	struct gw_header *header = NULL;
	char *blob = NULL;
	enum kcgi_err kerr;

	if (pledge("stdio rpath wpath cpath proc exec sendfd unveil",
	    NULL) == -1)
		return got_error_from_errno("pledge");

	if ((header = gw_init_header()) == NULL)
		return got_error_from_errno("malloc");

	error = gw_apply_unveil(gw_trans->gw_dir->path, NULL);
	if (error)
		goto done;

	error = gw_get_header(gw_trans, header, 1);
	if (error)
		goto done;

	error = gw_get_file_read_blob(&blob, gw_trans);
	if (error)
		goto done;

	if (gw_trans->mime == KMIME_APP_OCTET_STREAM)
		goto done;
	else {
		kerr = khttp_puts(gw_trans->gw_req, blob);
		if (kerr != KCGI_OK)
			error = gw_kcgi_error(kerr);
	}
done:
	got_ref_list_free(&header->refs);
	gw_free_headers(header);
	free(blob);
	return error;
}

static const struct got_error *
gw_diff(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	struct gw_header *header = NULL;
	char *diff = NULL, *diff_html = NULL, *diff_html_disp = NULL;
	char *age = NULL, *age_html = NULL;
	enum kcgi_err kerr;

	if (pledge("stdio rpath wpath cpath proc exec sendfd unveil",
	    NULL) == -1)
		return got_error_from_errno("pledge");

	if ((header = gw_init_header()) == NULL)
		return got_error_from_errno("malloc");

	error = gw_apply_unveil(gw_trans->gw_dir->path, NULL);
	if (error)
		goto done;

	error = gw_get_header(gw_trans, header, 1);
	if (error)
		goto done;

	diff_html = gw_get_diff(gw_trans, header);

	if (diff_html == NULL) {
		diff_html = strdup("");
		if (diff_html == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
	}

	error = gw_get_time_str(&age, header->committer_time, TM_LONG);
	if (error)
		goto done;
	if (asprintf(&age_html, header_age_html, age ? age : "") == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}
	if (asprintf(&diff_html_disp, diff_header,
	    gw_gen_diff_header(header->parent_id, header->commit_id),
	    gw_gen_commit_header(header->commit_id, header->refs_str),
	    gw_gen_tree_header(header->tree_id),
	    gw_gen_author_header(header->author),
	    gw_gen_committer_header(header->committer), age_html,
	    gw_gen_commit_msg_header(gw_html_escape(header->commit_msg)),
	    diff_html) == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}

	if (asprintf(&diff, diff_wrapper, diff_html_disp) == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}

	kerr = khttp_puts(gw_trans->gw_req, diff);
	if (kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
done:
	got_ref_list_free(&header->refs);
	gw_free_headers(header);
	free(diff_html_disp);
	free(diff_html);
	free(diff);
	free(age);
	free(age_html);
	return error;
}

static const struct got_error *
gw_index(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	struct gw_dir *gw_dir = NULL;
	char *html, *navs, *next, *prev;
	unsigned int prev_disp = 0, next_disp = 1, dir_c = 0;
	enum kcgi_err kerr;

	if (pledge("stdio rpath proc exec sendfd unveil",
	    NULL) == -1) {
		error = got_error_from_errno("pledge");
		return error;
	}

	error = gw_apply_unveil(gw_trans->gw_conf->got_repos_path, NULL);
	if (error)
		return error;

	error = gw_load_got_paths(gw_trans);
	if (error)
		return error;

	kerr = khttp_puts(gw_trans->gw_req, index_projects_header);
	if (kerr != KCGI_OK)
		return gw_kcgi_error(kerr);

	if (TAILQ_EMPTY(&gw_trans->gw_dirs)) {
		if (asprintf(&html, index_projects_empty,
		    gw_trans->gw_conf->got_repos_path) == -1)
			return got_error_from_errno("asprintf");
		kerr = khttp_puts(gw_trans->gw_req, html);
		if (kerr != KCGI_OK)
			error = gw_kcgi_error(kerr);
		free(html);
		return error;
	}

	TAILQ_FOREACH(gw_dir, &gw_trans->gw_dirs, entry)
		dir_c++;

	TAILQ_FOREACH(gw_dir, &gw_trans->gw_dirs, entry) {
		if (gw_trans->page > 0 && (gw_trans->page *
		    gw_trans->gw_conf->got_max_repos_display) > prev_disp) {
			prev_disp++;
			continue;
		}

		prev_disp++;

		if (error)
			return error;
		if(asprintf(&navs, index_navs, gw_dir->name, gw_dir->name,
		    gw_dir->name, gw_dir->name) == -1)
			return got_error_from_errno("asprintf");

		if (asprintf(&html, index_projects, gw_dir->name, gw_dir->name,
		    gw_dir->description, gw_dir->owner ? gw_dir->owner : "",
		    gw_dir->age,
		    navs) == -1)
			return got_error_from_errno("asprintf");

		kerr = khttp_puts(gw_trans->gw_req, html);
		free(navs);
		free(html);
		if (kerr != KCGI_OK)
			return gw_kcgi_error(kerr);

		if (gw_trans->gw_conf->got_max_repos_display == 0)
			continue;

		if (next_disp == gw_trans->gw_conf->got_max_repos_display) {
			kerr = khttp_puts(gw_trans->gw_req, np_wrapper_start);
			if (kerr != KCGI_OK)
				return gw_kcgi_error(kerr);
		} else if ((gw_trans->gw_conf->got_max_repos_display > 0) &&
		    (gw_trans->page > 0) &&
		    (next_disp == gw_trans->gw_conf->got_max_repos_display ||
		    prev_disp == gw_trans->repos_total)) {
			kerr = khttp_puts(gw_trans->gw_req, np_wrapper_start);
			if (kerr != KCGI_OK)
				return gw_kcgi_error(kerr);
		}

		if ((gw_trans->gw_conf->got_max_repos_display > 0) &&
		    (gw_trans->page > 0) &&
		    (next_disp == gw_trans->gw_conf->got_max_repos_display ||
		    prev_disp == gw_trans->repos_total)) {
			if (asprintf(&prev, nav_prev, gw_trans->page - 1) == -1)
				return got_error_from_errno("asprintf");
			kerr = khttp_puts(gw_trans->gw_req, prev);
			free(prev);
			if (kerr != KCGI_OK)
				return gw_kcgi_error(kerr);
		}

		kerr = khttp_puts(gw_trans->gw_req, div_end);
		if (kerr != KCGI_OK)
			return gw_kcgi_error(kerr);

		if (gw_trans->gw_conf->got_max_repos_display > 0 &&
		    next_disp == gw_trans->gw_conf->got_max_repos_display &&
		    dir_c != (gw_trans->page + 1) *
		    gw_trans->gw_conf->got_max_repos_display) {
			if (asprintf(&next, nav_next, gw_trans->page + 1) == -1)
				return got_error_from_errno("calloc");
			kerr = khttp_puts(gw_trans->gw_req, next);
			free(next);
			if (kerr != KCGI_OK)
				return gw_kcgi_error(kerr);
			kerr = khttp_puts(gw_trans->gw_req, div_end);
			if (kerr != KCGI_OK)
				error = gw_kcgi_error(kerr);
			next_disp = 0;
			break;
		}

		if ((gw_trans->gw_conf->got_max_repos_display > 0) &&
		    (gw_trans->page > 0) &&
		    (next_disp == gw_trans->gw_conf->got_max_repos_display ||
		    prev_disp == gw_trans->repos_total)) {
			kerr = khttp_puts(gw_trans->gw_req, div_end);
			if (kerr != KCGI_OK)
				return gw_kcgi_error(kerr);
		}

		next_disp++;
	}
	return error;
}

static const struct got_error *
gw_commits(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	char *commits_html, *commits_navs_html;
	struct gw_header *header = NULL, *n_header = NULL;
	char *age = NULL, *age_html = NULL;
	enum kcgi_err kerr;

	if ((header = gw_init_header()) == NULL)
		return got_error_from_errno("malloc");

	if (pledge("stdio rpath proc exec sendfd unveil",
	    NULL) == -1) {
		error = got_error_from_errno("pledge");
		goto done;
	}

	error = gw_apply_unveil(gw_trans->gw_dir->path, NULL);
	if (error)
		goto done;

	error = gw_get_header(gw_trans, header,
	    gw_trans->gw_conf->got_max_commits_display);
	if (error)
		goto done;

	kerr = khttp_puts(gw_trans->gw_req, commits_wrapper);
	if (kerr != KCGI_OK) {
		error = gw_kcgi_error(kerr);
		goto done;
	}
	TAILQ_FOREACH(n_header, &gw_trans->gw_headers, entry) {
		if (asprintf(&commits_navs_html, commits_navs,
		    gw_trans->repo_name, n_header->commit_id,
		    gw_trans->repo_name, n_header->commit_id,
		    gw_trans->repo_name, n_header->commit_id) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}
		error = gw_get_time_str(&age, n_header->committer_time,
		    TM_LONG);
		if (error)
			goto done;
		if (asprintf(&age_html, header_age_html, age ? age : "") == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}
		if (asprintf(&commits_html, commits_line,
		    gw_gen_commit_header(n_header->commit_id,
		        n_header->refs_str),
		    gw_gen_author_header(n_header->author),
		    gw_gen_committer_header(n_header->committer),
		    age_html,
		    gw_html_escape(n_header->commit_msg),
		    commits_navs_html) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}
		free(age);
		age = NULL;
		free(age_html);
		age_html = NULL;
		kerr = khttp_puts(gw_trans->gw_req, commits_html);
		if (kerr != KCGI_OK) {
			error = gw_kcgi_error(kerr);
			goto done;
		}
	}
	kerr = khttp_puts(gw_trans->gw_req, div_end);
	if (kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
done:
	got_ref_list_free(&header->refs);
	gw_free_headers(header);
	TAILQ_FOREACH(n_header, &gw_trans->gw_headers, entry)
		gw_free_headers(n_header);
	free(age);
	free(age_html);
	return error;
}

static const struct got_error *
gw_briefs(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	char *briefs_html = NULL, *briefs_navs_html = NULL, *newline;
	struct gw_header *header = NULL, *n_header = NULL;
	char *age = NULL, *age_html = NULL;
	enum kcgi_err kerr;

	if ((header = gw_init_header()) == NULL)
		return got_error_from_errno("malloc");

	if (pledge("stdio rpath proc exec sendfd unveil",
	    NULL) == -1) {
		error = got_error_from_errno("pledge");
		goto done;
	}

	error = gw_apply_unveil(gw_trans->gw_dir->path, NULL);
	if (error)
		goto done;

	if (gw_trans->action == GW_SUMMARY)
		error = gw_get_header(gw_trans, header, D_MAXSLCOMMDISP);
	else
		error = gw_get_header(gw_trans, header,
		    gw_trans->gw_conf->got_max_commits_display);
	if (error)
		goto done;

	kerr = khttp_puts(gw_trans->gw_req, briefs_wrapper);
	if (kerr != KCGI_OK) {
		error = gw_kcgi_error(kerr);
		goto done;
	}

	TAILQ_FOREACH(n_header, &gw_trans->gw_headers, entry) {
		if (asprintf(&briefs_navs_html, briefs_navs,
		    gw_trans->repo_name, n_header->commit_id,
		    gw_trans->repo_name, n_header->commit_id,
		    gw_trans->repo_name, n_header->commit_id) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}
		newline = strchr(n_header->commit_msg, '\n');
		if (newline)
			*newline = '\0';
		error = gw_get_time_str(&age, n_header->committer_time,
		    TM_DIFF);
		if (error)
			goto done;
		if (asprintf(&age_html, header_age_html, age ? age : "") == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}
		if (asprintf(&briefs_html, briefs_line, age_html,
		    n_header->author, gw_html_escape(n_header->commit_msg),
		    briefs_navs_html) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}
		free(age);
		age = NULL;
		free(age_html);
		age_html = NULL;
		kerr = khttp_puts(gw_trans->gw_req, briefs_html);
		if (kerr != KCGI_OK) {
			error = gw_kcgi_error(kerr);
			goto done;
		}
	}
	kerr = khttp_puts(gw_trans->gw_req, div_end);
	if (kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
done:
	got_ref_list_free(&header->refs);
	gw_free_headers(header);
	TAILQ_FOREACH(n_header, &gw_trans->gw_headers, entry)
		gw_free_headers(n_header);
	free(age);
	free(age_html);
	return error;
}

static const struct got_error *
gw_summary(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	char *description_html = NULL, *repo_owner_html = NULL;
	char *age = NULL, *repo_age_html = NULL, *cloneurl_html = NULL;
	char *tags = NULL, *tags_html = NULL;
	char *heads = NULL, *heads_html = NULL;
	enum kcgi_err kerr;

	if (pledge("stdio rpath proc exec sendfd unveil", NULL) == -1)
		return got_error_from_errno("pledge");

	/* unveil is applied with gw_briefs below */

	kerr = khttp_puts(gw_trans->gw_req, summary_wrapper);
	if (kerr != KCGI_OK)
		return gw_kcgi_error(kerr);

	if (gw_trans->gw_conf->got_show_repo_description) {
		if (gw_trans->gw_dir->description != NULL &&
		    (strcmp(gw_trans->gw_dir->description, "") != 0)) {
			if (asprintf(&description_html, description,
			    gw_trans->gw_dir->description) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}

			kerr = khttp_puts(gw_trans->gw_req, description_html);
			if (kerr != KCGI_OK) {
				error = gw_kcgi_error(kerr);
				goto done;
			}
		}
	}

	if (gw_trans->gw_conf->got_show_repo_owner &&
	    gw_trans->gw_dir->owner != NULL) {
		if (asprintf(&repo_owner_html, repo_owner,
		    gw_trans->gw_dir->owner) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}

		kerr = khttp_puts(gw_trans->gw_req, repo_owner_html);
		if (kerr != KCGI_OK) {
			error = gw_kcgi_error(kerr);
			goto done;
		}
	}

	if (gw_trans->gw_conf->got_show_repo_age) {
		error = gw_get_repo_age(&age, gw_trans, gw_trans->gw_dir->path,
		    "refs/heads", TM_LONG);
		if (error)
			goto done;
		if (age != NULL) {
			if (asprintf(&repo_age_html, last_change, age) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}

			kerr = khttp_puts(gw_trans->gw_req, repo_age_html);
			if (kerr != KCGI_OK) {
				error = gw_kcgi_error(kerr);
				goto done;
			}
		}
	}

	if (gw_trans->gw_conf->got_show_repo_cloneurl) {
		if (gw_trans->gw_dir->url != NULL &&
		    (strcmp(gw_trans->gw_dir->url, "") != 0)) {
			if (asprintf(&cloneurl_html, cloneurl,
			    gw_trans->gw_dir->url) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}

			kerr = khttp_puts(gw_trans->gw_req, cloneurl_html);
			if (kerr != KCGI_OK) {
				error = gw_kcgi_error(kerr);
				goto done;
			}
		}
	}
	kerr = khttp_puts(gw_trans->gw_req, div_end);
	if (kerr != KCGI_OK) {
		error = gw_kcgi_error(kerr);
		goto done;
	}

	error = gw_briefs(gw_trans);
	if (error)
		goto done;

	tags = gw_get_repo_tags(gw_trans, NULL, D_MAXSLCOMMDISP, TAGBRIEF);
	heads = gw_get_repo_heads(gw_trans);

	if (tags != NULL && strcmp(tags, "") != 0) {
		if (asprintf(&tags_html, summary_tags, tags) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}
		kerr = khttp_puts(gw_trans->gw_req, tags_html);
		if (kerr != KCGI_OK) {
			error = gw_kcgi_error(kerr);
			goto done;
		}
	}

	if (heads != NULL && strcmp(heads, "") != 0) {
		if (asprintf(&heads_html, summary_heads, heads) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}
		kerr = khttp_puts(gw_trans->gw_req, heads_html);
		if (kerr != KCGI_OK) {
			error = gw_kcgi_error(kerr);
			goto done;
		}
	}
done:
	free(description_html);
	free(repo_owner_html);
	free(age);
	free(repo_age_html);
	free(cloneurl_html);
	free(tags);
	free(tags_html);
	free(heads);
	free(heads_html);
	return error;
}

static const struct got_error *
gw_tree(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	struct gw_header *header = NULL;
	char *tree = NULL, *tree_html = NULL, *tree_html_disp = NULL;
	char *age = NULL, *age_html = NULL;
	enum kcgi_err kerr;

	if (pledge("stdio rpath proc exec sendfd unveil", NULL) == -1)
		return got_error_from_errno("pledge");

	if ((header = gw_init_header()) == NULL)
		return got_error_from_errno("malloc");

	error = gw_apply_unveil(gw_trans->gw_dir->path, NULL);
	if (error)
		goto done;

	error = gw_get_header(gw_trans, header, 1);
	if (error)
		goto done;

	tree_html = gw_get_repo_tree(gw_trans);

	if (tree_html == NULL) {
		tree_html = strdup("");
		if (tree_html == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
	}

	error = gw_get_time_str(&age, header->committer_time, TM_LONG);
	if (error)
		goto done;
	if (asprintf(&age_html, header_age_html, age ? age : "") == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}
	if (asprintf(&tree_html_disp, tree_header, age_html,
	    gw_gen_commit_msg_header(gw_html_escape(header->commit_msg)),
	    tree_html) == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}

	if (asprintf(&tree, tree_wrapper, tree_html_disp) == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}

	kerr = khttp_puts(gw_trans->gw_req, tree);
	if (kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
done:
	got_ref_list_free(&header->refs);
	gw_free_headers(header);
	free(tree_html_disp);
	free(tree_html);
	free(tree);
	free(age);
	free(age_html);
	return error;
}

static const struct got_error *
gw_tag(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	struct gw_header *header = NULL;
	char *tag = NULL, *tag_html = NULL, *tag_html_disp = NULL;
	enum kcgi_err kerr;

	if (pledge("stdio rpath proc exec sendfd unveil", NULL) == -1)
		return got_error_from_errno("pledge");

	if ((header = gw_init_header()) == NULL)
		return got_error_from_errno("malloc");

	error = gw_apply_unveil(gw_trans->gw_dir->path, NULL);
	if (error)
		goto done;

	error = gw_get_header(gw_trans, header, 1);
	if (error)
		goto done;

	tag_html = gw_get_repo_tags(gw_trans, header, 1, TAGFULL);
	if (tag_html == NULL) {
		tag_html = strdup("");
		if (tag_html == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
	}

	if (asprintf(&tag_html_disp, tag_header,
	    gw_gen_commit_header(header->commit_id, header->refs_str),
	    gw_gen_commit_msg_header(gw_html_escape(header->commit_msg)),
	    tag_html) == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}

	if (asprintf(&tag, tag_wrapper, tag_html_disp) == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}

	kerr = khttp_puts(gw_trans->gw_req, tag);
	if (kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
done:
	got_ref_list_free(&header->refs);
	gw_free_headers(header);
	free(tag_html_disp);
	free(tag_html);
	free(tag);
	return error;
}

static const struct got_error *
gw_load_got_path(struct gw_trans *gw_trans, struct gw_dir *gw_dir)
{
	const struct got_error *error = NULL;
	DIR *dt;
	char *dir_test;
	int opened = 0;

	if (asprintf(&dir_test, "%s/%s/%s",
	    gw_trans->gw_conf->got_repos_path, gw_dir->name,
	    GOTWEB_GIT_DIR) == -1)
		return got_error_from_errno("asprintf");

	dt = opendir(dir_test);
	if (dt == NULL) {
		free(dir_test);
	} else {
		gw_dir->path = strdup(dir_test);
		opened = 1;
		goto done;
	}

	if (asprintf(&dir_test, "%s/%s/%s",
	    gw_trans->gw_conf->got_repos_path, gw_dir->name,
	    GOTWEB_GOT_DIR) == -1)
		return got_error_from_errno("asprintf");

	dt = opendir(dir_test);
	if (dt == NULL)
		free(dir_test);
	else {
		opened = 1;
		error = got_error(GOT_ERR_NOT_GIT_REPO);
		goto errored;
	}

	if (asprintf(&dir_test, "%s/%s",
	    gw_trans->gw_conf->got_repos_path, gw_dir->name) == -1)
		return got_error_from_errno("asprintf");

	gw_dir->path = strdup(dir_test);

done:
	error = gw_get_repo_description(&gw_dir->description, gw_trans,
	    gw_dir->path);
	if (error)
		goto errored;
	error = gw_get_repo_owner(&gw_dir->owner, gw_trans, gw_dir->path);
	if (error)
		goto errored;
	error = gw_get_repo_age(&gw_dir->age, gw_trans, gw_dir->path,
	    "refs/heads", TM_DIFF);
	if (error)
		goto errored;
	error = gw_get_clone_url(&gw_dir->url, gw_trans, gw_dir->path);
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
		if (asprintf(&gw_trans->repo_name, "%s", p->parsed.s) == -1)
			return got_error_from_errno("asprintf");

		if (asprintf(&gw_trans->repo_path, "%s/%s",
		    gw_trans->gw_conf->got_repos_path, p->parsed.s) == -1)
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
					if (asprintf(&gw_trans->action_name,
					    "%s", action->func_name) == -1)
						return
						    got_error_from_errno(
						    "asprintf");

					break;
				}

				action = NULL;
			}

 		if ((p = gw_trans->gw_req->fieldmap[KEY_COMMIT_ID]))
			if (asprintf(&gw_trans->commit, "%s",
			    p->parsed.s) == -1)
				return got_error_from_errno("asprintf");

		if ((p = gw_trans->gw_req->fieldmap[KEY_FILE]))
			if (asprintf(&gw_trans->repo_file, "%s",
			    p->parsed.s) == -1)
				return got_error_from_errno("asprintf");

		if ((p = gw_trans->gw_req->fieldmap[KEY_FOLDER]))
			if (asprintf(&gw_trans->repo_folder, "%s",
			    p->parsed.s) == -1)
				return got_error_from_errno("asprintf");

		if ((p = gw_trans->gw_req->fieldmap[KEY_HEADREF]))
			if (asprintf(&gw_trans->headref, "%s",
			    p->parsed.s) == -1)
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

	return error;
}

static struct gw_dir *
gw_init_gw_dir(char *dir)
{
	struct gw_dir *gw_dir;

	if ((gw_dir = malloc(sizeof(*gw_dir))) == NULL)
		return NULL;

	if (asprintf(&gw_dir->name, "%s", dir) == -1)
		return NULL;

	return gw_dir;
}

static const struct got_error *
gw_display_open(struct gw_trans *gw_trans, enum khttp code, enum kmime mime)
{
	enum kcgi_err kerr;

	kerr = khttp_head(gw_trans->gw_req, kresps[KRESP_ALLOW], "GET");
	if (kerr != KCGI_OK)
		return gw_kcgi_error(kerr);
	kerr = khttp_head(gw_trans->gw_req, kresps[KRESP_STATUS], "%s",
	    khttps[code]);
	if (kerr != KCGI_OK)
		return gw_kcgi_error(kerr);
	kerr = khttp_head(gw_trans->gw_req, kresps[KRESP_CONTENT_TYPE], "%s",
	    kmimetypes[mime]);
	if (kerr != KCGI_OK)
		return gw_kcgi_error(kerr);
	kerr = khttp_head(gw_trans->gw_req, "X-Content-Type-Options",
	    "nosniff");
	if (kerr != KCGI_OK)
		return gw_kcgi_error(kerr);
	kerr = khttp_head(gw_trans->gw_req, "X-Frame-Options", "DENY");
	if (kerr != KCGI_OK)
		return gw_kcgi_error(kerr);
	kerr = khttp_head(gw_trans->gw_req, "X-XSS-Protection",
	    "1; mode=block");
	if (kerr != KCGI_OK)
		return gw_kcgi_error(kerr);

	if (gw_trans->mime == KMIME_APP_OCTET_STREAM) {
		kerr = khttp_head(gw_trans->gw_req,
		    kresps[KRESP_CONTENT_DISPOSITION],
		    "attachment; filename=%s", gw_trans->repo_file);
		if (kerr != KCGI_OK)
			return gw_kcgi_error(kerr);
	}

	kerr = khttp_body(gw_trans->gw_req);
	return gw_kcgi_error(kerr);
}

static const struct got_error *
gw_display_index(struct gw_trans *gw_trans)
{
	const struct got_error *error;
	enum kcgi_err kerr;

	error = gw_display_open(gw_trans, KHTTP_200, gw_trans->mime);
	if (error)
		return error;

	kerr = khtml_open(gw_trans->gw_html_req, gw_trans->gw_req, 0);
	if (kerr)
		return gw_kcgi_error(kerr);

	if (gw_trans->action != GW_BLOB) {
		kerr = khttp_template(gw_trans->gw_req, gw_trans->gw_tmpl,
		    gw_query_funcs[gw_trans->action].template);
		if (kerr != KCGI_OK) {
			khtml_close(gw_trans->gw_html_req);
			return gw_kcgi_error(kerr);
		}
	}

	return gw_kcgi_error(khtml_close(gw_trans->gw_html_req));
}

static void
gw_display_error(struct gw_trans *gw_trans, const struct got_error *err)
{
	if (gw_display_open(gw_trans, KHTTP_200, gw_trans->mime) != NULL)
		return;

	if (khtml_open(gw_trans->gw_html_req, gw_trans->gw_req, 0) != KCGI_OK)
		return;

	khttp_puts(gw_trans->gw_req, err->msg);
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
			if (asprintf(&site_owner_name_h, site_owner,
			    site_owner_name) == -1)
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
	}
	return 1;
}

static char *
gw_gen_commit_header(char *str1, char *str2)
{
	char *return_html = NULL, *ref_str = NULL;

	if (strcmp(str2, "") != 0) {
		if (asprintf(&ref_str, "(%s)", str2) == -1) {
			return_html = strdup("");
			return return_html;
		}
	} else
		ref_str = strdup("");


	if (asprintf(&return_html, header_commit_html, str1, ref_str) == -1)
		return_html = strdup("");

	free(ref_str);
	return return_html;
}

static char *
gw_gen_diff_header(char *str1, char *str2)
{
	char *return_html = NULL;

	if (asprintf(&return_html, header_diff_html, str1, str2) == -1)
		return_html = strdup("");

	return return_html;
}

static char *
gw_gen_author_header(char *str)
{
	char *return_html = NULL;

	if (asprintf(&return_html, header_author_html, str) == -1)
		return_html = strdup("");

	return return_html;
}

static char *
gw_gen_committer_header(char *str)
{
	char *return_html = NULL;

	if (asprintf(&return_html, header_committer_html, str) == -1)
		return_html = strdup("");

	return return_html;
}

static char *
gw_gen_commit_msg_header(char *str)
{
	char *return_html = NULL;

	if (asprintf(&return_html, header_commit_msg_html, str) == -1)
		return_html = strdup("");

	return return_html;
}

static char *
gw_gen_tree_header(char *str)
{
	char *return_html = NULL;

	if (asprintf(&return_html, header_tree_html, str) == -1)
		return_html = strdup("");

	return return_html;
}

static const struct got_error *
gw_get_repo_description(char **description, struct gw_trans *gw_trans,
    char *dir)
{
	const struct got_error *error = NULL;
	FILE *f = NULL;
	char *d_file = NULL;
	unsigned int len;
	size_t n;

	*description = NULL;
	if (gw_trans->gw_conf->got_show_repo_description == 0)
		return gw_empty_string(description);

	if (asprintf(&d_file, "%s/description", dir) == -1)
		return got_error_from_errno("asprintf");

	f = fopen(d_file, "r");
	if (f == NULL) {
		if (errno == ENOENT || errno == EACCES)
			return gw_empty_string(description);
		error = got_error_from_errno2("fopen", d_file);
		goto done;
	}

	if (fseek(f, 0, SEEK_END) == -1) {
		error = got_ferror(f, GOT_ERR_IO);
		goto done;
	}
	len = ftell(f);
	if (len == -1) {
		error = got_ferror(f, GOT_ERR_IO);
		goto done;
	}
	if (fseek(f, 0, SEEK_SET) == -1) {
		error = got_ferror(f, GOT_ERR_IO);
		goto done;
	}
	*description = calloc(len + 1, sizeof(**description));
	if (*description == NULL) {
		error = got_error_from_errno("calloc");
		goto done;
	}

	n = fread(*description, 1, len, f);
	if (n == 0 && ferror(f))
		error = got_ferror(f, GOT_ERR_IO);
done:
	if (f != NULL && fclose(f) == -1 && error == NULL)
		error = got_error_from_errno("fclose");
	free(d_file);
	return error;
}

static const struct got_error *
gw_get_time_str(char **repo_age, time_t committer_time, int ref_tm)
{
	struct tm tm;
	time_t diff_time;
	char *years = "years ago", *months = "months ago";
	char *weeks = "weeks ago", *days = "days ago", *hours = "hours ago";
	char *minutes = "minutes ago", *seconds = "seconds ago";
	char *now = "right now";
	char *s;
	char datebuf[29];

	*repo_age = NULL;

	switch (ref_tm) {
	case TM_DIFF:
		diff_time = time(NULL) - committer_time;
		if (diff_time > 60 * 60 * 24 * 365 * 2) {
			if (asprintf(repo_age, "%lld %s",
			    (diff_time / 60 / 60 / 24 / 365), years) == -1)
				return got_error_from_errno("asprintf");
		} else if (diff_time > 60 * 60 * 24 * (365 / 12) * 2) {
			if (asprintf(repo_age, "%lld %s",
			    (diff_time / 60 / 60 / 24 / (365 / 12)),
			    months) == -1)
				return got_error_from_errno("asprintf");
		} else if (diff_time > 60 * 60 * 24 * 7 * 2) {
			if (asprintf(repo_age, "%lld %s",
			    (diff_time / 60 / 60 / 24 / 7), weeks) == -1)
				return got_error_from_errno("asprintf");
		} else if (diff_time > 60 * 60 * 24 * 2) {
			if (asprintf(repo_age, "%lld %s",
			    (diff_time / 60 / 60 / 24), days) == -1)
				return got_error_from_errno("asprintf");
		} else if (diff_time > 60 * 60 * 2) {
			if (asprintf(repo_age, "%lld %s",
			    (diff_time / 60 / 60), hours) == -1)
				return got_error_from_errno("asprintf");
		} else if (diff_time > 60 * 2) {
			if (asprintf(repo_age, "%lld %s", (diff_time / 60),
			    minutes) == -1)
				return got_error_from_errno("asprintf");
		} else if (diff_time > 2) {
			if (asprintf(repo_age, "%lld %s", diff_time,
			    seconds) == -1)
				return got_error_from_errno("asprintf");
		} else {
			if (asprintf(repo_age, "%s", now) == -1)
				return got_error_from_errno("asprintf");
		}
		break;
	case TM_LONG:
		if (gmtime_r(&committer_time, &tm) == NULL)
			return got_error_from_errno("gmtime_r");

		s = asctime_r(&tm, datebuf);
		if (s == NULL)
			return got_error_from_errno("asctime_r");

		if (asprintf(repo_age, "%s UTC", datebuf) == -1)
			return got_error_from_errno("asprintf");
		break;
	}
	return NULL;
}

static const struct got_error *
gw_get_repo_age(char **repo_age, struct gw_trans *gw_trans, char *dir,
    char *repo_ref, int ref_tm)
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

	*repo_age = NULL;
	SIMPLEQ_INIT(&refs);

	if (repo_ref == NULL)
		return NULL;

	if (strncmp(repo_ref, "refs/heads/", 11) == 0)
		is_head = 1;

	if (gw_trans->gw_conf->got_show_repo_age == 0)
		return NULL;

	error = got_repo_open(&repo, dir, NULL);
	if (error)
		goto done;

	if (is_head)
		error = got_ref_list(&refs, repo, "refs/heads",
		    got_ref_cmp_by_name, NULL);
	else
		error = got_ref_list(&refs, repo, repo_ref,
		    got_ref_cmp_by_name, NULL);
	if (error)
		goto done;

	SIMPLEQ_FOREACH(re, &refs, entry) {
		if (is_head)
			refname = strdup(repo_ref);
		else
			refname = got_ref_get_name(re->ref);
		error = got_ref_open(&head_ref, repo, refname, 0);
		if (error)
			goto done;

		error = got_ref_resolve(&id, repo, head_ref);
		got_ref_close(head_ref);
		if (error)
			goto done;

		error = got_object_open_as_commit(&commit, repo, id);
		if (error)
			goto done;

		committer_time =
		    got_object_commit_get_committer_time(commit);

		if (cmp_time < committer_time)
			cmp_time = committer_time;
	}

	if (cmp_time != 0) {
		committer_time = cmp_time;
		error = gw_get_time_str(repo_age, committer_time, ref_tm);
	}
done:
	got_ref_list_free(&refs);
	free(id);
	return error;
}

static char *
gw_get_diff(struct gw_trans *gw_trans, struct gw_header *header)
{
	const struct got_error *error;
	FILE *f = NULL;
	struct got_object_id *id1 = NULL, *id2 = NULL;
	struct buf *diffbuf = NULL;
	char *label1 = NULL, *label2 = NULL, *diff_html = NULL, *buf = NULL;
	char *buf_color = NULL, *n_buf = NULL, *newline = NULL;
	int obj_type;
	size_t newsize;

	f = got_opentemp();
	if (f == NULL)
		return NULL;

	error = buf_alloc(&diffbuf, 0);
	if (error)
		return NULL;

	error = got_repo_open(&header->repo, gw_trans->repo_path, NULL);
	if (error)
		goto done;

	if (strncmp(header->parent_id, "/dev/null", 9) != 0) {
		error = got_repo_match_object_id(&id1, &label1,
			header->parent_id, GOT_OBJ_TYPE_ANY, 1, header->repo);
		if (error)
			goto done;
	}

	error = got_repo_match_object_id(&id2, &label2,
	    header->commit_id, GOT_OBJ_TYPE_ANY, 1, header->repo);
	if (error)
		goto done;

	error = got_object_get_type(&obj_type, header->repo, id2);
	if (error)
		goto done;
	switch (obj_type) {
	case GOT_OBJ_TYPE_BLOB:
		error = got_diff_objects_as_blobs(id1, id2, NULL, NULL, 3, 0,
		    header->repo, f);
		break;
	case GOT_OBJ_TYPE_TREE:
		error = got_diff_objects_as_trees(id1, id2, "", "", 3, 0,
		    header->repo, f);
		break;
	case GOT_OBJ_TYPE_COMMIT:
		error = got_diff_objects_as_commits(id1, id2, 3, 0,
		    header->repo, f);
		break;
	default:
		error = got_error(GOT_ERR_OBJ_TYPE);
	}

	if (error)
		goto done;

	if ((buf = calloc(128, sizeof(char *))) == NULL)
		goto done;

	if (fseek(f, 0, SEEK_SET) == -1)
		goto done;

	while ((fgets(buf, 2048, f)) != NULL) {
		if (ferror(f))
			goto done;
		n_buf = buf;
		while (*n_buf == '\n')
			n_buf++;
		newline = strchr(n_buf, '\n');
		if (newline)
			*newline = ' ';

		buf_color = gw_colordiff_line(gw_html_escape(n_buf));
		if (buf_color == NULL)
			continue;

		error = buf_puts(&newsize, diffbuf, buf_color);
		if (error)
			goto done;

		error = buf_puts(&newsize, diffbuf, div_end);
		if (error)
			goto done;
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

	if (error)
		return NULL;
	else
		return diff_html;
}

static const struct got_error *
gw_get_repo_owner(char **owner, struct gw_trans *gw_trans, char *dir)
{
	const struct got_error *error = NULL;
	struct got_repository *repo;
	const char *gitconfig_owner;

	*owner = NULL;

	if (gw_trans->gw_conf->got_show_repo_owner == 0)
		return NULL;

	error = got_repo_open(&repo, dir, NULL);
	if (error)
		return error;
	gitconfig_owner = got_repo_get_gitconfig_owner(repo);
	if (gitconfig_owner) {
		*owner = strdup(gitconfig_owner);
		if (*owner == NULL)
			error = got_error_from_errno("strdup");
	}
	got_repo_close(repo);
	return error;
}

static const struct got_error *
gw_get_clone_url(char **url, struct gw_trans *gw_trans, char *dir)
{
	const struct got_error *error = NULL;
	FILE *f;
	char *d_file = NULL;
	unsigned int len;
	size_t n;

	*url = NULL;

	if (asprintf(&d_file, "%s/cloneurl", dir) == -1)
		return got_error_from_errno("asprintf");

	f = fopen(d_file, "r");
	if (f == NULL) {
		if (errno != ENOENT && errno != EACCES)
			error = got_error_from_errno2("fopen", d_file);
		goto done;
	}

	if (fseek(f, 0, SEEK_END) == -1) {
		error = got_ferror(f, GOT_ERR_IO);
		goto done;
	}
	len = ftell(f);
	if (len == -1) {
		error = got_ferror(f, GOT_ERR_IO);
		goto done;
	}
	if (fseek(f, 0, SEEK_SET) == -1) {
		error = got_ferror(f, GOT_ERR_IO);
		goto done;
	}

	*url = calloc(len + 1, sizeof(**url));
	if (*url == NULL) {
		error = got_error_from_errno("calloc");
		goto done;
	}

	n = fread(*url, 1, len, f);
	if (n == 0 && ferror(f))
		error = got_ferror(f, GOT_ERR_IO);
done:
	if (f && fclose(f) == -1 && error == NULL)
		error = got_error_from_errno("fclose");
	free(d_file);
	return NULL;
}

static char *
gw_get_repo_tags(struct gw_trans *gw_trans, struct gw_header *header, int limit,
    int tag_type)
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;
	char *tags = NULL, *tag_row = NULL, *tags_navs_disp = NULL;
	char *age = NULL, *age_html = NULL, *newline, *time_str = NULL;
	struct buf *diffbuf = NULL;
	size_t newsize;

	SIMPLEQ_INIT(&refs);

	error = buf_alloc(&diffbuf, 0);
	if (error)
		return NULL;

	error = got_repo_open(&repo, gw_trans->repo_path, NULL);
	if (error)
		goto done;

	error = got_ref_list(&refs, repo, "refs/tags", got_ref_cmp_tags, repo);
	if (error)
		goto done;

	SIMPLEQ_FOREACH(re, &refs, entry) {
		const char *refname;
		char *refstr, *tag_commit0, *tag_commit, *id_str;
		const char *tagger;
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

		tagger = got_object_tag_get_tagger(tag);
		tagger_time = got_object_tag_get_tagger_time(tag);

		error = got_object_id_str(&id_str,
		    got_object_tag_get_object_id(tag));
		if (error)
			goto done;

		tag_commit0 = strdup(got_object_tag_get_message(tag));

		if (tag_commit0 == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}

		tag_commit = tag_commit0;
		while (*tag_commit == '\n')
			tag_commit++;

		switch (tag_type) {
		case TAGBRIEF:
			newline = strchr(tag_commit, '\n');
			if (newline)
				*newline = '\0';

			error = gw_get_time_str(&age, tagger_time, TM_DIFF);
			if (error)
				goto done;

			if (asprintf(&tags_navs_disp, tags_navs,
			    gw_trans->repo_name, id_str, gw_trans->repo_name,
			    id_str, gw_trans->repo_name, id_str,
			    gw_trans->repo_name, id_str) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}

			if (asprintf(&tag_row, tags_row, age ? age : "",
			    refname, tag_commit, tags_navs_disp) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}

			free(tags_navs_disp);
			break;
		case TAGFULL:
			error = gw_get_time_str(&age, tagger_time, TM_LONG);
			if (error)
				goto done;
			if (asprintf(&tag_row, tag_info, age ? age : "",
			    gw_html_escape(tagger),
			    gw_html_escape(tag_commit)) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}
			break;
		default:
			break;
		}

		got_object_tag_close(tag);

		error = buf_puts(&newsize, diffbuf, tag_row);

		free(id_str);
		free(refstr);
		free(age);
		age = NULL;
		free(age_html);
		age_html = NULL;
		free(tag_commit0);
		free(tag_row);

		if (error || (limit && --limit == 0))
			break;
	}

	if (buf_len(diffbuf) > 0) {
		error = buf_putc(diffbuf, '\0');
		tags = strdup(buf_get(diffbuf));
	}
done:
	free(time_str);
	buf_free(diffbuf);
	got_ref_list_free(&refs);
	if (repo)
		got_repo_close(repo);
	free(age);
	free(age_html);
	if (error)
		return NULL;
	else
		return tags;
}

static void
gw_free_headers(struct gw_header *header)
{
	free(header->id);
	free(header->path);
	if (header->commit != NULL)
		got_object_commit_close(header->commit);
	if (header->repo)
		got_repo_close(header->repo);
	free(header->refs_str);
	free(header->commit_id);
	free(header->parent_id);
	free(header->tree_id);
	free(header->author);
	free(header->committer);
	free(header->commit_msg);
}

static struct gw_header *
gw_init_header()
{
	struct gw_header *header;

	header = malloc(sizeof(*header));
	if (header == NULL)
		return NULL;

	header->repo = NULL;
	header->commit = NULL;
	header->id = NULL;
	header->path = NULL;
	SIMPLEQ_INIT(&header->refs);

	return header;
}

static const struct got_error *
gw_get_commits(struct gw_trans * gw_trans, struct gw_header *header,
    int limit)
{
	const struct got_error *error = NULL;
	struct got_commit_graph *graph = NULL;

	error = got_commit_graph_open(&graph, header->path, 0);
	if (error)
		goto done;

	error = got_commit_graph_iter_start(graph, header->id, header->repo,
	    NULL, NULL);
	if (error)
		goto done;

	for (;;) {
		error = got_commit_graph_iter_next(&header->id, graph,
		    header->repo, NULL, NULL);
		if (error) {
			if (error->code == GOT_ERR_ITER_COMPLETED)
				error = NULL;
			goto done;
		}
		if (header->id == NULL)
			goto done;

		error = got_object_open_as_commit(&header->commit, header->repo,
		    header->id);
		if (error)
			goto done;

		error = gw_get_commit(gw_trans, header);
		if (limit > 1) {
			struct gw_header *n_header = NULL;
			if ((n_header = gw_init_header()) == NULL) {
				error = got_error_from_errno("malloc");
				goto done;
			}

			n_header->refs_str = strdup(header->refs_str);
			n_header->commit_id = strdup(header->commit_id);
			n_header->parent_id = strdup(header->parent_id);
			n_header->tree_id = strdup(header->tree_id);
			n_header->author = strdup(header->author);
			n_header->committer = strdup(header->committer);
			n_header->commit_msg = strdup(header->commit_msg);
			n_header->committer_time = header->committer_time;
			TAILQ_INSERT_TAIL(&gw_trans->gw_headers, n_header,
			    entry);
		}
		if (error || (limit && --limit == 0))
			break;
	}
done:
	if (graph)
		got_commit_graph_close(graph);
	return error;
}

static const struct got_error *
gw_get_commit(struct gw_trans *gw_trans, struct gw_header *header)
{
	const struct got_error *error = NULL;
	struct got_reflist_entry *re;
	struct got_object_id *id2 = NULL;
	struct got_object_qid *parent_id;
	char *refs_str = NULL, *commit_msg = NULL, *commit_msg0;

	/*print commit*/
	SIMPLEQ_FOREACH(re, &header->refs, entry) {
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
			error = got_object_open_as_tag(&tag, header->repo,
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
		    got_object_tag_get_object_id(tag) : re->id, header->id);
		if (tag)
			got_object_tag_close(tag);
		if (cmp != 0)
			continue;
		s = refs_str;
		if (asprintf(&refs_str, "%s%s%s", s ? s : "",
		    s ? ", " : "", name) == -1) {
			error = got_error_from_errno("asprintf");
			free(s);
			return error;
		}
		header->refs_str = strdup(refs_str);
		free(s);
	}

	if (refs_str == NULL)
		header->refs_str = strdup("");
	free(refs_str);

	error = got_object_id_str(&header->commit_id, header->id);
	if (error)
		return error;

	error = got_object_id_str(&header->tree_id,
	    got_object_commit_get_tree_id(header->commit));
	if (error)
		return error;

	if (gw_trans->action == GW_DIFF) {
		parent_id = SIMPLEQ_FIRST(
		    got_object_commit_get_parent_ids(header->commit));
		if (parent_id != NULL) {
			id2 = got_object_id_dup(parent_id->id);
			free (parent_id);
			error = got_object_id_str(&header->parent_id, id2);
			if (error)
				return error;
			free(id2);
		} else
			header->parent_id = strdup("/dev/null");
	} else
		header->parent_id = strdup("");

	header->committer_time =
	    got_object_commit_get_committer_time(header->commit);

	if (gw_trans->action != GW_BRIEFS && gw_trans->action != GW_SUMMARY) {
		header->author = strdup(
	 	    gw_html_escape(got_object_commit_get_author(header->commit))
		);
	} else {
		header->author = strdup(
		    got_object_commit_get_author(header->commit)
		);
	}

	header->committer = strdup(
		gw_html_escape(got_object_commit_get_committer(header->commit))
	);

	error = got_object_commit_get_logmsg(&commit_msg0, header->commit);
	if (error)
		return error;

	commit_msg = commit_msg0;
	while (*commit_msg == '\n')
		commit_msg++;

	header->commit_msg = strdup(commit_msg);
	free(commit_msg0);
	return error;
}

static const struct got_error *
gw_get_header(struct gw_trans *gw_trans, struct gw_header *header, int limit)
{
	const struct got_error *error = NULL;
	char *in_repo_path = NULL;

	error = got_repo_open(&header->repo, gw_trans->repo_path, NULL);
	if (error)
		return error;

	if (gw_trans->commit == NULL) {
		struct got_reference *head_ref;
		error = got_ref_open(&head_ref, header->repo,
		    gw_trans->headref, 0);
		if (error)
			return error;

		error = got_ref_resolve(&header->id, header->repo, head_ref);
		got_ref_close(head_ref);
		if (error)
			return error;

		error = got_object_open_as_commit(&header->commit,
		    header->repo, header->id);
	} else {
		struct got_reference *ref;
		error = got_ref_open(&ref, header->repo, gw_trans->commit, 0);
		if (error == NULL) {
			int obj_type;
			error = got_ref_resolve(&header->id, header->repo, ref);
			got_ref_close(ref);
			if (error)
				return error;
			error = got_object_get_type(&obj_type, header->repo,
			    header->id);
			if (error)
				return error;
			if (obj_type == GOT_OBJ_TYPE_TAG) {
				struct got_tag_object *tag;
				error = got_object_open_as_tag(&tag,
				    header->repo, header->id);
				if (error)
					return error;
				if (got_object_tag_get_object_type(tag) !=
				    GOT_OBJ_TYPE_COMMIT) {
					got_object_tag_close(tag);
					error = got_error(GOT_ERR_OBJ_TYPE);
					return error;
				}
				free(header->id);
				header->id = got_object_id_dup(
				    got_object_tag_get_object_id(tag));
				if (header->id == NULL)
					error = got_error_from_errno(
					    "got_object_id_dup");
				got_object_tag_close(tag);
				if (error)
					return error;
			} else if (obj_type != GOT_OBJ_TYPE_COMMIT) {
				error = got_error(GOT_ERR_OBJ_TYPE);
				return error;
			}
			error = got_object_open_as_commit(&header->commit,
			    header->repo, header->id);
			if (error)
				return error;
		}
		if (header->commit == NULL) {
			error = got_repo_match_object_id_prefix(&header->id,
			    gw_trans->commit, GOT_OBJ_TYPE_COMMIT,
			    header->repo);
			if (error)
				return error;
		}
		error = got_repo_match_object_id_prefix(&header->id,
			    gw_trans->commit, GOT_OBJ_TYPE_COMMIT,
			    header->repo);
	}

	error = got_repo_map_path(&in_repo_path, header->repo,
	    gw_trans->repo_path, 1);
	if (error)
		return error;

	if (in_repo_path) {
		header->path = strdup(in_repo_path);
	}
	free(in_repo_path);

	error = got_ref_list(&header->refs, header->repo, NULL,
	    got_ref_cmp_by_name, NULL);
	if (error)
		return error;

	error = gw_get_commits(gw_trans, header, limit);
	return error;
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

		if (a->gw_trans->repo_folder == NULL)
			a->gw_trans->repo_folder = strdup("");
		if (a->gw_trans->repo_folder == NULL)
			goto err;
		asprintf(&blame_row, blame_line, a->nlines_prec, a->lineno_cur,
		    a->gw_trans->repo_name, bline->id_str,
		    a->gw_trans->repo_file, a->gw_trans->repo_folder,
		    bline->id_str, bline->datebuf, committer, line_escape);
		a->lineno_cur++;
		err = buf_puts(&newsize, a->blamebuf, blame_row);
		if (err)
			return err;

		bline = &a->lines[a->lineno_cur - 1];
err:
		free(line_escape);
		free(blame_row);
	}
done:
	if (commit)
		got_object_commit_close(commit);
	free(line);
	return err;
}

static int
isbinary(const char *buf, size_t n)
{
	return (memchr(buf, '\0', n) != NULL);
}

static const struct got_error *
gw_get_file_blame_blob(char **blame_html, struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_object_id *obj_id = NULL;
	struct got_object_id *commit_id = NULL;
	struct got_blob_object *blob = NULL;
	char *path = NULL, *in_repo_path = NULL;
	struct gw_blame_cb_args bca;
	int i, obj_type;
	size_t filesize;

	*blame_html = NULL;

	error = got_repo_open(&repo, gw_trans->repo_path, NULL);
	if (error)
		return error;

	if (asprintf(&path, "%s%s%s",
	    gw_trans->repo_folder ? gw_trans->repo_folder : "",
	    gw_trans->repo_folder ? "/" : "",
	    gw_trans->repo_file) == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}

	error = got_repo_map_path(&in_repo_path, repo, path, 1);
	if (error)
		goto done;

	error = got_repo_match_object_id(&commit_id, NULL, gw_trans->commit,
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
	if (error)
		goto done;
	if (buf_len(bca.blamebuf) > 0) {
		error = buf_putc(bca.blamebuf, '\0');
		if (error)
			goto done;
		*blame_html = strdup(buf_get(bca.blamebuf));
		if (*blame_html == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
	}
done:
	free(bca.line_offsets);
	free(bca.blamebuf);
	free(in_repo_path);
	free(commit_id);
	free(obj_id);
	free(path);

	for (i = 0; i < bca.nlines; i++) {
		struct blame_line *bline = &bca.lines[i];
		free(bline->id_str);
		free(bline->committer);
	}
	free(bca.lines);
	if (bca.f && fclose(bca.f) == EOF && error == NULL)
		error = got_error_from_errno("fclose");
	if (blob)
		got_object_blob_close(blob);
	if (repo)
		got_repo_close(repo);
	return error;
}

static const struct got_error *
gw_get_file_read_blob(char **blobstr, struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_object_id *obj_id = NULL;
	struct got_object_id *commit_id = NULL;
	struct got_blob_object *blob = NULL;
	char *path = NULL, *in_repo_path = NULL;
	int obj_type;
	size_t filesize, n;
	enum kcgi_err kerr;
	FILE *f = NULL;

	*blobstr = NULL;

	error = got_repo_open(&repo, gw_trans->repo_path, NULL);
	if (error)
		return error;

	if (asprintf(&path, "%s%s%s",
	    gw_trans->repo_folder ? gw_trans->repo_folder : "",
	    gw_trans->repo_folder ? "/" : "",
	    gw_trans->repo_file) == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}

	error = got_repo_map_path(&in_repo_path, repo, path, 1);
	if (error)
		goto done;

	error = got_repo_match_object_id(&commit_id, NULL, gw_trans->commit,
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

	f = got_opentemp();
	if (f == NULL) {
		error = got_error_from_errno("got_opentemp");
		goto done;
	}
	error = got_object_blob_dump_to_file(&filesize, NULL, NULL, f, blob);
	if (error)
		goto done;

	/* XXX This will fail on large files... */
	*blobstr = calloc(filesize + 1, sizeof(**blobstr));
	if (*blobstr == NULL) {
		error = got_error_from_errno("calloc");
		goto done;
	}

	n = fread(*blobstr, 1, filesize, f);
	if (n == 0) {
		if (ferror(f))
			error = got_ferror(f, GOT_ERR_IO);
		goto done;
	}

	if (isbinary(*blobstr, n))
		gw_trans->mime = KMIME_APP_OCTET_STREAM;
	else
		gw_trans->mime = KMIME_TEXT_PLAIN;

	error = gw_display_index(gw_trans);
	if (error)
		goto done;

	if (gw_trans->mime == KMIME_APP_OCTET_STREAM) {
		kerr = khttp_write(gw_trans->gw_req, *blobstr, filesize);
		if (kerr != KCGI_OK)
			error = gw_kcgi_error(kerr);
	}
done:
	free(in_repo_path);
	free(commit_id);
	free(obj_id);
	free(path);
	if (blob)
		got_object_blob_close(blob);
	if (repo)
		got_repo_close(repo);
	if (f != NULL && fclose(f) == -1 && error == NULL)
		error = got_error_from_errno("fclose");
	return error;
}

static char*
gw_get_repo_tree(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_object_id *tree_id = NULL, *commit_id = NULL;
	struct got_tree_object *tree = NULL;
	struct buf *diffbuf = NULL;
	size_t newsize;
	char *tree_html = NULL, *path = NULL, *in_repo_path = NULL,
	    *tree_row = NULL, *id_str, *class = NULL;
	int nentries, i, class_flip = 0;

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

	if (gw_trans->commit == NULL) {
		struct got_reference *head_ref;
		error = got_ref_open(&head_ref, repo, gw_trans->headref, 0);
		if (error)
			goto done;

		error = got_ref_resolve(&commit_id, repo, head_ref);
		got_ref_close(head_ref);

	} else
		error = got_repo_match_object_id(&commit_id, NULL,
		    gw_trans->commit, GOT_OBJ_TYPE_COMMIT, 1, repo);
	if (error)
		goto done;

	error = got_object_id_str(&gw_trans->commit, commit_id);
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

		if (asprintf(&id, "%s", id_str) == -1) {
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

		if (class_flip == 0) {
			class = strdup("back_lightgray");
			class_flip = 1;
		} else {
			class = strdup("back_white");
			class_flip = 0;
		}

		char *build_folder = NULL;
		if (S_ISDIR(got_tree_entry_get_mode(te))) {
			if (gw_trans->repo_folder != NULL) {
				if (asprintf(&build_folder, "%s/%s",
				    gw_trans->repo_folder,
				    got_tree_entry_get_name(te)) == -1) {
					error =
					    got_error_from_errno("asprintf");
					goto done;
				}
			} else {
				if (asprintf(&build_folder, "/%s",
				    got_tree_entry_get_name(te)) == -1)
					goto done;
			}

			if (asprintf(&url_html, folder_html,
			    gw_trans->repo_name, gw_trans->action_name,
			    gw_trans->commit, build_folder,
			    got_tree_entry_get_name(te), modestr) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}

		if (asprintf(&tree_row, tree_line, class, url_html,
			class) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}

		} else {
			if (gw_trans->repo_folder != NULL) {
				if (asprintf(&build_folder, "%s",
				    gw_trans->repo_folder) == -1) {
					error =
					    got_error_from_errno("asprintf");
					goto done;
				}
			} else
				build_folder = strdup("");

			if (asprintf(&url_html, file_html, gw_trans->repo_name,
			    "blob", gw_trans->commit,
			    got_tree_entry_get_name(te), build_folder,
			    got_tree_entry_get_name(te), modestr) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}

			if (asprintf(&tree_row, tree_line_with_navs, class,
				url_html, class, gw_trans->repo_name, "blob",
				gw_trans->commit, got_tree_entry_get_name(te),
				build_folder, "blob", gw_trans->repo_name,
				"blame", gw_trans->commit,
				got_tree_entry_get_name(te), build_folder,
				"blame") == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}
		}
		free(build_folder);

		if (error)
			goto done;

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

	SIMPLEQ_INIT(&refs);

	error = buf_alloc(&diffbuf, 0);
	if (error)
		return NULL;

	error = got_repo_open(&repo, gw_trans->repo_path, NULL);
	if (error)
		goto done;

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

		error = gw_get_repo_age(&age, gw_trans, gw_trans->gw_dir->path,
		    refname, TM_DIFF);
		if (error)
			goto done;

		if (asprintf(&head_navs_disp, heads_navs, gw_trans->repo_name,
		    refname, gw_trans->repo_name, refname,
		    gw_trans->repo_name, refname, gw_trans->repo_name,
		    refname) == -1) {
			error = got_error_from_errno("asprintf");
			goto done;
		}

		if (strncmp(refname, "refs/heads/", 11) == 0)
			refname += 11;

		if (asprintf(&head_row, heads_row, age, refname,
		    head_navs_disp) == -1) {
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

	if (asprintf(&link, got_link, gw_trans->gw_conf->got_logo_url,
	    gw_trans->gw_conf->got_logo) == -1)
		return NULL;

	return link;
}

static char *
gw_get_site_link(struct gw_trans *gw_trans)
{
	char *link, *repo = "", *action = "";

	if (gw_trans->repo_name != NULL)
		if (asprintf(&repo, " / <a href='?path=%s&action=summary'>%s" \
		    "</a>", gw_trans->repo_name, gw_trans->repo_name) == -1)
			return NULL;

	if (gw_trans->action_name != NULL)
		if (asprintf(&action, " / %s", gw_trans->action_name) == -1)
			return NULL;

	if (asprintf(&link, site_link, GOTWEB,
	    gw_trans->gw_conf->got_site_link, repo, action) == -1)
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

	if (buf == NULL)
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

	if (asprintf(&div_diff_line_div, div_diff_line, color) == -1)
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
main(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	struct gw_trans *gw_trans;
	struct gw_dir *dir = NULL, *tdir;
	const char *page = "index";
	int gw_malloc = 1;
	enum kcgi_err kerr;

	if ((gw_trans = malloc(sizeof(struct gw_trans))) == NULL)
		errx(1, "malloc");

	if ((gw_trans->gw_req = malloc(sizeof(struct kreq))) == NULL)
		errx(1, "malloc");

	if ((gw_trans->gw_html_req = malloc(sizeof(struct khtmlreq))) == NULL)
		errx(1, "malloc");

	if ((gw_trans->gw_tmpl = malloc(sizeof(struct ktemplate))) == NULL)
		errx(1, "malloc");

	kerr = khttp_parse(gw_trans->gw_req, gw_keys, KEY__ZMAX, &page, 1, 0);
	if (kerr != KCGI_OK) {
		error = gw_kcgi_error(kerr);
		goto done;
	}

	if ((gw_trans->gw_conf =
	    malloc(sizeof(struct gotweb_conf))) == NULL) {
		gw_malloc = 0;
		error = got_error_from_errno("malloc");
		goto done;
	}

	TAILQ_INIT(&gw_trans->gw_dirs);
	TAILQ_INIT(&gw_trans->gw_headers);

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
	if (error)
		goto done;

	error = gw_parse_querystring(gw_trans);
	if (error)
		goto done;

	if (gw_trans->action == GW_BLOB)
		error = gw_blob(gw_trans);
	else
		error = gw_display_index(gw_trans);
done:
	if (error) {
		gw_trans->mime = KMIME_TEXT_PLAIN;
		gw_trans->action = GW_ERR;
		gw_display_error(gw_trans, error);
	}
	if (gw_malloc) {
		free(gw_trans->gw_conf->got_repos_path);
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
	return 0;
}
