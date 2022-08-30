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
#include <sha1.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <got_error.h>
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

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

struct gw_trans {
	TAILQ_HEAD(headers, gw_header)	 gw_headers;
	TAILQ_HEAD(dirs, gw_dir)	 gw_dirs;
	struct got_repository	*repo;
	struct gw_dir		*gw_dir;
	struct gotweb_config	*gw_conf;
	struct ktemplate	*gw_tmpl;
	struct khtmlreq		*gw_html_req;
	struct kreq		*gw_req;
	const struct got_error	*error;
	const char		*repo_name;
	char			*repo_path;
	char			*commit_id;
	char			*next_id;
	char			*prev_id;
	const char		*repo_file;
	char			*repo_folder;
	const char		*headref;
	unsigned int		 action;
	unsigned int		 page;
	unsigned int		 repos_total;
	enum kmime		 mime;
	int			*pack_fds;
};

struct gw_header {
	TAILQ_ENTRY(gw_header)		 entry;
	struct got_reflist_head		 refs;
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
	KEY_PREV_ID,
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

enum gw_tags_type {
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
	{ kvalid_stringne,	"prev" },
};

static struct gw_header		*gw_init_header(void);

static void			 gw_free_header(struct gw_header *);

static int			 gw_template(size_t, void *);

static const struct got_error	*gw_error(struct gw_trans *);
static const struct got_error	*gw_init_gw_dir(struct gw_dir **, const char *);
static const struct got_error	*gw_get_repo_description(char **,
				    struct gw_trans *, char *);
static const struct got_error	*gw_get_repo_owner(char **, struct gw_trans *,
				    char *);
static const struct got_error	*gw_get_time_str(char **, time_t, int);
static const struct got_error	*gw_get_repo_age(char **, struct gw_trans *,
				    char *, const char *, int);
static const struct got_error	*gw_output_file_blame(struct gw_trans *,
				    struct gw_header *);
static const struct got_error	*gw_output_blob_buf(struct gw_trans *,
				    struct gw_header *);
static const struct got_error	*gw_output_repo_tree(struct gw_trans *,
				    struct gw_header *);
static const struct got_error	*gw_output_diff(struct gw_trans *,
				    struct gw_header *);
static const struct got_error	*gw_output_repo_tags(struct gw_trans *,
				    struct gw_header *, int, int);
static const struct got_error	*gw_output_repo_heads(struct gw_trans *);
static const struct got_error	*gw_output_site_link(struct gw_trans *);
static const struct got_error	*gw_get_clone_url(char **, struct gw_trans *,
				    char *);
static const struct got_error	*gw_colordiff_line(struct gw_trans *, char *);

static const struct got_error	*gw_gen_commit_header(struct gw_trans *, char *,
				    char*);
static const struct got_error	*gw_gen_diff_header(struct gw_trans *, char *,
				    char*);
static const struct got_error	*gw_gen_author_header(struct gw_trans *,
				    const char *);
static const struct got_error	*gw_gen_age_header(struct gw_trans *,
				    const char *);
static const struct got_error	*gw_gen_committer_header(struct gw_trans *,
				    const char *);
static const struct got_error	*gw_gen_commit_msg_header(struct gw_trans*,
				    char *);
static const struct got_error	*gw_gen_tree_header(struct gw_trans *, char *);
static const struct got_error	*gw_display_open(struct gw_trans *, enum khttp,
				    enum kmime);
static const struct got_error	*gw_display_index(struct gw_trans *);
static const struct got_error	*gw_get_header(struct gw_trans *,
				    struct gw_header *, int);
static const struct got_error	*gw_get_commits(struct gw_trans *,
				    struct gw_header *, int,
				    struct got_object_id *);
static const struct got_error	*gw_get_commit(struct gw_trans *,
				    struct gw_header *,
				    struct got_commit_object *,
				    struct got_object_id *);
static const struct got_error	*gw_apply_unveil(const char *);
static const struct got_error	*gw_blame_cb(void *, int, int,
				    struct got_commit_object *,
				    struct got_object_id *);
static const struct got_error	*gw_load_got_paths(struct gw_trans *);
static const struct got_error	*gw_load_got_path(struct gw_trans *,
				    struct gw_dir *);
static const struct got_error	*gw_parse_querystring(struct gw_trans *);
static const struct got_error	*gw_blame(struct gw_trans *);
static const struct got_error	*gw_blob(struct gw_trans *);
static const struct got_error	*gw_diff(struct gw_trans *);
static const struct got_error	*gw_index(struct gw_trans *);
static const struct got_error	*gw_commits(struct gw_trans *);
static const struct got_error	*gw_briefs(struct gw_trans *);
static const struct got_error	*gw_summary(struct gw_trans *);
static const struct got_error	*gw_tree(struct gw_trans *);
static const struct got_error	*gw_tag(struct gw_trans *);
static const struct got_error	*gw_tags(struct gw_trans *);

struct gw_query_action {
	unsigned int		 func_id;
	const char		*func_name;
	const struct got_error	*(*func_main)(struct gw_trans *);
	const char		*template;
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
	GW_TAGS,
	GW_TREE,
};

static const struct gw_query_action gw_query_funcs[] = {
	{ GW_BLAME,	"blame",	gw_blame,	"gw_tmpl/blame.tmpl" },
	{ GW_BLOB,	"blob",		NULL,		NULL },
	{ GW_BRIEFS,	"briefs",	gw_briefs,	"gw_tmpl/briefs.tmpl" },
	{ GW_COMMITS,	"commits",	gw_commits,	"gw_tmpl/commit.tmpl" },
	{ GW_DIFF,	"diff",		gw_diff,	"gw_tmpl/diff.tmpl" },
	{ GW_ERR,	"error",	gw_error,	"gw_tmpl/err.tmpl" },
	{ GW_INDEX,	"index",	gw_index,	"gw_tmpl/index.tmpl" },
	{ GW_SUMMARY,	"summary",	gw_summary,	"gw_tmpl/summry.tmpl" },
	{ GW_TAG,	"tag",		gw_tag,		"gw_tmpl/tag.tmpl" },
	{ GW_TAGS,	"tags",		gw_tags,	"gw_tmpl/tags.tmpl" },
	{ GW_TREE,	"tree",		gw_tree,	"gw_tmpl/tree.tmpl" },
};

static const char *
gw_get_action_name(struct gw_trans *gw_trans)
{
	return gw_query_funcs[gw_trans->action].func_name;
}

static const struct got_error *
gw_kcgi_error(enum kcgi_err kerr)
{
	if (kerr == KCGI_OK)
		return NULL;

	if (kerr == KCGI_EXIT || kerr == KCGI_HUP)
		return got_error(GOT_ERR_CANCELLED);

	if (kerr == KCGI_ENOMEM)
		return got_error_set_errno(ENOMEM,
		    kcgi_strerror(kerr));

	if (kerr == KCGI_ENFILE)
		return got_error_set_errno(ENFILE,
		    kcgi_strerror(kerr));

	if (kerr == KCGI_EAGAIN)
		return got_error_set_errno(EAGAIN,
		    kcgi_strerror(kerr));

	if (kerr == KCGI_FORM)
		return got_error_msg(GOT_ERR_IO,
		    kcgi_strerror(kerr));

	return got_error_from_errno(kcgi_strerror(kerr));
}

static const struct got_error *
gw_apply_unveil(const char *repo_path)
{
	const struct got_error *err;

#ifdef PROFILE
	if (unveil("gmon.out", "rwc") != 0)
		return got_error_from_errno2("unveil", "gmon.out");
#endif
	if (repo_path && unveil(repo_path, "r") != 0)
		return got_error_from_errno2("unveil", repo_path);

	if (unveil(GOT_TMPDIR_STR, "rwc") != 0)
		return got_error_from_errno2("unveil", GOT_TMPDIR_STR);

	err = got_privsep_unveil_exec_helpers();
	if (err != NULL)
		return err;

	if (unveil(NULL, NULL) != 0)
		return got_error_from_errno("unveil");

	return NULL;
}

static int
isbinary(const uint8_t *buf, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		if (buf[i] == 0)
			return 1;
	return 0;
}

static const struct got_error *
gw_blame(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	struct gw_header *header = NULL;
	char *age = NULL;
	enum kcgi_err kerr = KCGI_OK;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath proc exec sendfd unveil",
	    NULL) == -1)
		return got_error_from_errno("pledge");
#endif
	if ((header = gw_init_header()) == NULL)
		return got_error_from_errno("malloc");

	error = gw_apply_unveil(gw_trans->gw_dir->path);
	if (error)
		goto done;

	/* check querystring */
	if (gw_trans->repo_file == NULL) {
		error = got_error_msg(GOT_ERR_QUERYSTRING,
		    "file required in querystring");
		goto done;
	}
	if (gw_trans->commit_id == NULL) {
		error = got_error_msg(GOT_ERR_QUERYSTRING,
		    "commit required in querystring");
		goto done;
	}

	error = gw_get_header(gw_trans, header, 1);
	if (error)
		goto done;
	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
	    "blame_header_wrapper", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
	    "blame_header", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	error = gw_get_time_str(&age, header->committer_time,
	    TM_LONG);
	if (error)
		goto done;
	error = gw_gen_age_header(gw_trans, age ?age : "");
	if (error)
		goto done;
	error = gw_gen_commit_msg_header(gw_trans, header->commit_msg);
	if (error)
		goto done;
	kerr = khtml_closeelem(gw_trans->gw_html_req, 2);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
	    "dotted_line", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
	if (kerr != KCGI_OK)
		goto done;

	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
	    "blame", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	error = gw_output_file_blame(gw_trans, header);
	if (error)
		goto done;
	kerr = khtml_closeelem(gw_trans->gw_html_req, 2);
done:
	gw_free_header(header);
	if (error == NULL && kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
	return error;
}

static const struct got_error *
gw_blob(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL, *err = NULL;
	struct gw_header *header = NULL;
	enum kcgi_err kerr = KCGI_OK;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath proc exec sendfd unveil",
	    NULL) == -1)
		return got_error_from_errno("pledge");
#endif
	if ((header = gw_init_header()) == NULL)
		return got_error_from_errno("malloc");

	error = gw_apply_unveil(gw_trans->gw_dir->path);
	if (error)
		goto done;

	/* check querystring */
	if (gw_trans->repo_file == NULL) {
		error = got_error_msg(GOT_ERR_QUERYSTRING,
		    "file required in querystring");
		goto done;
	}
	if (gw_trans->commit_id == NULL) {
		error = got_error_msg(GOT_ERR_QUERYSTRING,
		    "commit required in querystring");
		goto done;
	}
	error = gw_get_header(gw_trans, header, 1);
	if (error)
		goto done;

	error = gw_output_blob_buf(gw_trans, header);
done:
	if (error) {
		gw_trans->mime = KMIME_TEXT_PLAIN;
		err = gw_display_index(gw_trans);
		if (err) {
			error = err;
			goto errored;
		}
		kerr = khttp_puts(gw_trans->gw_req, error->msg);
	}
errored:
	gw_free_header(header);
	if (error == NULL && kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
	return error;
}

static const struct got_error *
gw_diff(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	struct gw_header *header = NULL;
	char *age = NULL;
	enum kcgi_err kerr = KCGI_OK;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath proc exec sendfd unveil",
	    NULL) == -1)
		return got_error_from_errno("pledge");
#endif
	if ((header = gw_init_header()) == NULL)
		return got_error_from_errno("malloc");

	error = gw_apply_unveil(gw_trans->gw_dir->path);
	if (error)
		goto done;

	error = gw_get_header(gw_trans, header, 1);
	if (error)
		goto done;

	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
	    "diff_header_wrapper", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
	    "diff_header", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	error = gw_gen_diff_header(gw_trans, header->parent_id,
	    header->commit_id);
	if (error)
		goto done;
	error = gw_gen_commit_header(gw_trans, header->commit_id,
	    header->refs_str);
	if (error)
		goto done;
	error = gw_gen_tree_header(gw_trans, header->tree_id);
	if (error)
		goto done;
	error = gw_gen_author_header(gw_trans, header->author);
	if (error)
		goto done;
	error = gw_gen_committer_header(gw_trans, header->author);
	if (error)
		goto done;
	error = gw_get_time_str(&age, header->committer_time,
	    TM_LONG);
	if (error)
		goto done;
	error = gw_gen_age_header(gw_trans, age ?age : "");
	if (error)
		goto done;
	error = gw_gen_commit_msg_header(gw_trans, header->commit_msg);
	if (error)
		goto done;
	kerr = khtml_closeelem(gw_trans->gw_html_req, 2);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
	    "dotted_line", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
	if (kerr != KCGI_OK)
		goto done;

	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
	    "diff", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	error = gw_output_diff(gw_trans, header);
	if (error)
		goto done;

	kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
done:
	gw_free_header(header);
	free(age);
	if (error == NULL && kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
	return error;
}

static const struct got_error *
gw_index(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	struct gw_dir *gw_dir = NULL;
	char *href_next = NULL, *href_prev = NULL, *href_summary = NULL;
	char *href_briefs = NULL, *href_commits = NULL, *href_tree = NULL;
	char *href_tags = NULL;
	unsigned int prev_disp = 0, next_disp = 1, dir_c = 0;
	enum kcgi_err kerr = KCGI_OK;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath proc exec sendfd unveil",
	    NULL) == -1) {
		error = got_error_from_errno("pledge");
		return error;
	}
#endif
	error = gw_apply_unveil(gw_trans->gw_conf->got_repos_path);
	if (error)
		return error;

	error = gw_load_got_paths(gw_trans);
	if (error)
		return error;

	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
	    "index_header", KATTR__MAX);
	if (kerr != KCGI_OK)
		return gw_kcgi_error(kerr);
	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
	    "index_header_project", KATTR__MAX);
	if (kerr != KCGI_OK)
		return gw_kcgi_error(kerr);
	kerr = khtml_puts(gw_trans->gw_html_req, "Project");
	if (kerr != KCGI_OK)
		return gw_kcgi_error(kerr);
	kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
	if (kerr != KCGI_OK)
		return gw_kcgi_error(kerr);

	if (gw_trans->gw_conf->got_show_repo_description) {
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "index_header_description", KATTR__MAX);
		if (kerr != KCGI_OK)
			return gw_kcgi_error(kerr);
		kerr = khtml_puts(gw_trans->gw_html_req, "Description");
		if (kerr != KCGI_OK)
			return gw_kcgi_error(kerr);
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			return gw_kcgi_error(kerr);
	}

	if (gw_trans->gw_conf->got_show_repo_owner) {
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "index_header_owner", KATTR__MAX);
		if (kerr != KCGI_OK)
			return gw_kcgi_error(kerr);
		kerr = khtml_puts(gw_trans->gw_html_req, "Owner");
		if (kerr != KCGI_OK)
			return gw_kcgi_error(kerr);
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			return gw_kcgi_error(kerr);
	}

	if (gw_trans->gw_conf->got_show_repo_age) {
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "index_header_age", KATTR__MAX);
		if (kerr != KCGI_OK)
			return gw_kcgi_error(kerr);
		kerr = khtml_puts(gw_trans->gw_html_req, "Last Change");
		if (kerr != KCGI_OK)
			return gw_kcgi_error(kerr);
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			return gw_kcgi_error(kerr);
	}

	kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
	if (kerr != KCGI_OK)
		return gw_kcgi_error(kerr);

	if (TAILQ_EMPTY(&gw_trans->gw_dirs)) {
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "index_wrapper", KATTR__MAX);
		if (kerr != KCGI_OK)
			return gw_kcgi_error(kerr);
		kerr = khtml_printf(gw_trans->gw_html_req,
		    "No repositories found in %s",
		    gw_trans->gw_conf->got_repos_path);
		if (kerr != KCGI_OK)
			return gw_kcgi_error(kerr);
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			return gw_kcgi_error(kerr);
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "dotted_line", KATTR__MAX);
		if (kerr != KCGI_OK)
			return gw_kcgi_error(kerr);
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			return gw_kcgi_error(kerr);
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

		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "index_wrapper", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;

		href_summary = khttp_urlpart(NULL, NULL, "gotweb", "path",
		    gw_dir->name, "action", "summary", NULL);
		if (href_summary == NULL) {
			error = got_error_from_errno("khttp_urlpart");
			goto done;
		}
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "index_project", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A, KATTR_HREF,
		    href_summary, KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req, gw_dir->name);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 2);
		if (kerr != KCGI_OK)
			goto done;
		if (gw_trans->gw_conf->got_show_repo_description) {
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "index_project_description", KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_puts(gw_trans->gw_html_req,
			    gw_dir->description ? gw_dir->description : "");
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
			if (kerr != KCGI_OK)
				goto done;
		}
		if (gw_trans->gw_conf->got_show_repo_owner) {
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "index_project_owner", KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_puts(gw_trans->gw_html_req,
			    gw_dir->owner ? gw_dir->owner : "");
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
			if (kerr != KCGI_OK)
				goto done;
		}
		if (gw_trans->gw_conf->got_show_repo_age) {
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "index_project_age", KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_puts(gw_trans->gw_html_req,
			    gw_dir->age ? gw_dir->age : "");
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
			if (kerr != KCGI_OK)
				goto done;
		}

		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "navs_wrapper", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "navs", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;

		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A, KATTR_HREF,
		    href_summary, KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req, "summary");
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;

		kerr = khtml_puts(gw_trans->gw_html_req, " | ");
		if (kerr != KCGI_OK)
			goto done;

		href_briefs = khttp_urlpart(NULL, NULL, "gotweb", "path",
		    gw_dir->name, "action", "briefs", NULL);
		if (href_briefs == NULL) {
			error = got_error_from_errno("khttp_urlpart");
			goto done;
		}
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A, KATTR_HREF,
		    href_briefs, KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req, "commit briefs");
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			error = gw_kcgi_error(kerr);

		kerr = khtml_puts(gw_trans->gw_html_req, " | ");
		if (kerr != KCGI_OK)
			goto done;

		href_commits = khttp_urlpart(NULL, NULL, "gotweb", "path",
		    gw_dir->name, "action", "commits", NULL);
		if (href_commits == NULL) {
			error = got_error_from_errno("khttp_urlpart");
			goto done;
		}
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A, KATTR_HREF,
		    href_commits, KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req, "commits");
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;

		kerr = khtml_puts(gw_trans->gw_html_req, " | ");
		if (kerr != KCGI_OK)
			goto done;

		href_tags = khttp_urlpart(NULL, NULL, "gotweb", "path",
		    gw_dir->name, "action", "tags", NULL);
		if (href_tags == NULL) {
			error = got_error_from_errno("khttp_urlpart");
			goto done;
		}
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A, KATTR_HREF,
		    href_tags, KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req, "tags");
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;

		kerr = khtml_puts(gw_trans->gw_html_req, " | ");
		if (kerr != KCGI_OK)
			goto done;

		href_tree = khttp_urlpart(NULL, NULL, "gotweb", "path",
		    gw_dir->name, "action", "tree", NULL);
		if (href_tree == NULL) {
			error = got_error_from_errno("khttp_urlpart");
			goto done;
		}
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A, KATTR_HREF,
		    href_tree, KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req, "tree");
		if (kerr != KCGI_OK)
			goto done;

		kerr = khtml_closeelem(gw_trans->gw_html_req, 4);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "dotted_line", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;

		free(href_summary);
		href_summary = NULL;
		free(href_briefs);
		href_briefs = NULL;
		free(href_commits);
		href_commits = NULL;
		free(href_tags);
		href_tags = NULL;
		free(href_tree);
		href_tree = NULL;

		if (gw_trans->gw_conf->got_max_repos_display == 0)
			continue;

		if ((next_disp == gw_trans->gw_conf->got_max_repos_display) ||
		    ((gw_trans->gw_conf->got_max_repos_display > 0) &&
		    (gw_trans->page > 0) &&
		    (next_disp == gw_trans->gw_conf->got_max_repos_display ||
		    prev_disp == gw_trans->repos_total))) {
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "np_wrapper", KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "nav_prev", KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
		}

		if ((gw_trans->gw_conf->got_max_repos_display > 0) &&
		    (gw_trans->page > 0) &&
		    (next_disp == gw_trans->gw_conf->got_max_repos_display ||
		    prev_disp == gw_trans->repos_total)) {
			href_prev = khttp_urlpartx(NULL, NULL, "gotweb", "page",
			    KATTRX_INT, (int64_t)(gw_trans->page - 1), NULL);
			if (href_prev == NULL) {
				error = got_error_from_errno("khttp_urlpartx");
				goto done;
			}
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A,
			    KATTR_HREF, href_prev, KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_puts(gw_trans->gw_html_req, "Previous");
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
			if (kerr != KCGI_OK)
				goto done;
		}

		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			return gw_kcgi_error(kerr);

		if (gw_trans->gw_conf->got_max_repos_display > 0 &&
		    next_disp == gw_trans->gw_conf->got_max_repos_display &&
		    dir_c != (gw_trans->page + 1) *
		    gw_trans->gw_conf->got_max_repos_display) {
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "nav_next", KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			href_next = khttp_urlpartx(NULL, NULL, "gotweb", "page",
			    KATTRX_INT, (int64_t)(gw_trans->page + 1), NULL);
			if (href_next == NULL) {
				error = got_error_from_errno("khttp_urlpartx");
				goto done;
			}
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A,
			    KATTR_HREF, href_next, KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_puts(gw_trans->gw_html_req, "Next");
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_closeelem(gw_trans->gw_html_req, 3);
			if (kerr != KCGI_OK)
				goto done;
			next_disp = 0;
			break;
		}

		if ((gw_trans->gw_conf->got_max_repos_display > 0) &&
		    (gw_trans->page > 0) &&
		    (next_disp == gw_trans->gw_conf->got_max_repos_display ||
		    prev_disp == gw_trans->repos_total)) {
			kerr = khtml_closeelem(gw_trans->gw_html_req, 2);
			if (kerr != KCGI_OK)
				goto done;
		}
		next_disp++;
	}
done:
	free(href_prev);
	free(href_next);
	free(href_summary);
	free(href_briefs);
	free(href_commits);
	free(href_tags);
	free(href_tree);
	if (error == NULL && kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
	return error;
}

static const struct got_error *
gw_commits(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	struct gw_header *header = NULL, *n_header = NULL;
	char *age = NULL, *href_diff = NULL, *href_tree = NULL;
	char *href_prev = NULL, *href_next = NULL;
	enum kcgi_err kerr = KCGI_OK;
	int commit_found = 0;

	if ((header = gw_init_header()) == NULL)
		return got_error_from_errno("malloc");

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath proc exec sendfd unveil",
	    NULL) == -1) {
		error = got_error_from_errno("pledge");
		goto done;
	}
#endif
	error = gw_apply_unveil(gw_trans->gw_dir->path);
	if (error)
		goto done;

	error = gw_get_header(gw_trans, header,
	    gw_trans->gw_conf->got_max_commits_display);
	if (error)
		goto done;

	TAILQ_FOREACH(n_header, &gw_trans->gw_headers, entry) {
		if (commit_found == 0 && gw_trans->commit_id != NULL) {
			if (strcmp(gw_trans->commit_id,
			    n_header->commit_id) != 0)
				continue;
			else
				commit_found = 1;
		}
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "commits_line_wrapper", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		error = gw_gen_commit_header(gw_trans, n_header->commit_id,
		    n_header->refs_str);
		if (error)
			goto done;
		error = gw_gen_author_header(gw_trans, n_header->author);
		if (error)
			goto done;
		error = gw_gen_committer_header(gw_trans, n_header->author);
		if (error)
			goto done;
		error = gw_get_time_str(&age, n_header->committer_time,
		    TM_LONG);
		if (error)
			goto done;
		error = gw_gen_age_header(gw_trans, age ?age : "");
		if (error)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 2);
		if (kerr != KCGI_OK)
			goto done;

		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "dotted_line", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;

		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "commit", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khttp_puts(gw_trans->gw_req, n_header->commit_msg);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;

		href_diff = khttp_urlpart(NULL, NULL, "gotweb", "path",
		    gw_trans->repo_name, "action", "diff", "commit",
		    n_header->commit_id, NULL);
		if (href_diff == NULL) {
			error = got_error_from_errno("khttp_urlpart");
			goto done;
		}
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "navs_wrapper", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "navs", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A,
		    KATTR_HREF, href_diff, KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req, "diff");
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;

		kerr = khtml_puts(gw_trans->gw_html_req, " | ");
		if (kerr != KCGI_OK)
			goto done;

		href_tree = khttp_urlpart(NULL, NULL, "gotweb", "path",
		    gw_trans->repo_name, "action", "tree", "commit",
		    n_header->commit_id, NULL);
		if (href_tree == NULL) {
			error = got_error_from_errno("khttp_urlpart");
			goto done;
		}
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A,
		    KATTR_HREF, href_tree, KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		khtml_puts(gw_trans->gw_html_req, "tree");
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;

		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "solid_line", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 2);
		if (kerr != KCGI_OK)
			goto done;

		free(age);
		age = NULL;
	}

	if (gw_trans->next_id || gw_trans->prev_id) {
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "np_wrapper", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "nav_prev", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
	}

	if (gw_trans->prev_id) {
		href_prev = khttp_urlpartx(NULL, NULL, "gotweb", "path",
		    KATTRX_STRING, gw_trans->repo_name, "page",
		    KATTRX_INT, (int64_t) (gw_trans->page - 1), "action",
		    KATTRX_STRING, "commits", "commit", KATTRX_STRING,
		    gw_trans->prev_id ? gw_trans->prev_id : "", NULL);
		if (href_prev == NULL) {
			error = got_error_from_errno("khttp_urlpartx");
			goto done;
		}
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A,
		    KATTR_HREF, href_prev, KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req, "Previous");
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;
	}

	if (gw_trans->next_id || gw_trans->page > 0) {
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			return gw_kcgi_error(kerr);
	}

	if (gw_trans->next_id) {
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "nav_next", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		href_next = khttp_urlpartx(NULL, NULL, "gotweb", "path",
		    KATTRX_STRING, gw_trans->repo_name, "page",
		    KATTRX_INT, (int64_t) (gw_trans->page + 1), "action",
		    KATTRX_STRING, "commits", "commit", KATTRX_STRING,
		    gw_trans->next_id, NULL);
		if (href_next == NULL) {
			error = got_error_from_errno("khttp_urlpartx");
			goto done;
		}
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A,
		    KATTR_HREF, href_next, KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req, "Next");
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 3);
		if (kerr != KCGI_OK)
			goto done;
	}

	if (gw_trans->next_id || gw_trans->page > 0) {
		kerr = khtml_closeelem(gw_trans->gw_html_req, 2);
		if (kerr != KCGI_OK)
			goto done;
	}
done:
	gw_free_header(header);
	TAILQ_FOREACH(n_header, &gw_trans->gw_headers, entry)
		gw_free_header(n_header);
	free(age);
	free(href_next);
	free(href_prev);
	free(href_diff);
	free(href_tree);
	if (error == NULL && kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
	return error;
}

static const struct got_error *
gw_briefs(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	struct gw_header *header = NULL, *n_header = NULL;
	char *age = NULL, *href_diff = NULL, *href_tree = NULL;
	char *href_prev = NULL, *href_next = NULL;
	char *newline, *smallerthan;
	enum kcgi_err kerr = KCGI_OK;
	int commit_found = 0;

	if ((header = gw_init_header()) == NULL)
		return got_error_from_errno("malloc");

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath proc exec sendfd unveil",
	    NULL) == -1) {
		error = got_error_from_errno("pledge");
		goto done;
	}
#endif
	if (gw_trans->action != GW_SUMMARY) {
		error = gw_apply_unveil(gw_trans->gw_dir->path);
		if (error)
			goto done;
	}

	if (gw_trans->action == GW_SUMMARY)
		error = gw_get_header(gw_trans, header, D_MAXSLCOMMDISP);
	else
		error = gw_get_header(gw_trans, header,
		    gw_trans->gw_conf->got_max_commits_display);
	if (error)
		goto done;

	TAILQ_FOREACH(n_header, &gw_trans->gw_headers, entry) {
		if (commit_found == 0 && gw_trans->commit_id != NULL) {
			if (strcmp(gw_trans->commit_id,
			    n_header->commit_id) != 0)
				continue;
			else
				commit_found = 1;
		}
		error = gw_get_time_str(&age, n_header->committer_time,
		    TM_DIFF);
		if (error)
			goto done;

		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "briefs_wrapper", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;

		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "briefs_age", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req, age ? age : "");
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;

		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "briefs_author", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		smallerthan = strchr(n_header->author, '<');
		if (smallerthan)
			*smallerthan = '\0';
		kerr = khtml_puts(gw_trans->gw_html_req, n_header->author);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;

		href_diff = khttp_urlpart(NULL, NULL, "gotweb", "path",
		    gw_trans->repo_name, "action", "diff", "commit",
		    n_header->commit_id, NULL);
		if (href_diff == NULL) {
			error = got_error_from_errno("khttp_urlpart");
			goto done;
		}
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "briefs_log", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		newline = strchr(n_header->commit_msg, '\n');
		if (newline)
			*newline = '\0';
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A,
		    KATTR_HREF, href_diff, KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req, n_header->commit_msg);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;

		if (n_header->refs_str) {
			kerr = khtml_puts(gw_trans->gw_html_req, " ");
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_SPAN,
			    KATTR_ID, "refs_str", KATTR__MAX);
			if (kerr != KCGI_OK)
			goto done;
			kerr = khtml_printf(gw_trans->gw_html_req, "(%s)",
			    n_header->refs_str);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
			if (kerr != KCGI_OK)
				goto done;
		}

		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;

		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "navs_wrapper", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "navs", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A,
		    KATTR_HREF, href_diff, KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req, "diff");
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;

		kerr = khtml_puts(gw_trans->gw_html_req, " | ");
		if (kerr != KCGI_OK)
			goto done;

		href_tree = khttp_urlpart(NULL, NULL, "gotweb", "path",
		    gw_trans->repo_name, "action", "tree", "commit",
		    n_header->commit_id, NULL);
		if (href_tree == NULL) {
			error = got_error_from_errno("khttp_urlpart");
			goto done;
		}
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A,
		    KATTR_HREF, href_tree, KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		khtml_puts(gw_trans->gw_html_req, "tree");
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;

		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "dotted_line", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 3);
		if (kerr != KCGI_OK)
			goto done;

		free(age);
		age = NULL;
		free(href_diff);
		href_diff = NULL;
		free(href_tree);
		href_tree = NULL;
	}

	if (gw_trans->next_id || gw_trans->prev_id) {
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "np_wrapper", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "nav_prev", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
	}

	if (gw_trans->prev_id) {
		href_prev = khttp_urlpartx(NULL, NULL, "gotweb", "path",
		    KATTRX_STRING, gw_trans->repo_name, "page",
		    KATTRX_INT, (int64_t) (gw_trans->page - 1), "action",
		    KATTRX_STRING, "briefs", "commit", KATTRX_STRING,
		    gw_trans->prev_id ? gw_trans->prev_id : "", NULL);
		if (href_prev == NULL) {
			error = got_error_from_errno("khttp_urlpartx");
			goto done;
		}
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A,
		    KATTR_HREF, href_prev, KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req, "Previous");
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;
	}

	if (gw_trans->next_id || gw_trans->page > 0) {
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			return gw_kcgi_error(kerr);
	}

	if (gw_trans->next_id) {
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "nav_next", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;

		href_next = khttp_urlpartx(NULL, NULL, "gotweb", "path",
		    KATTRX_STRING, gw_trans->repo_name, "page",
		    KATTRX_INT, (int64_t) (gw_trans->page + 1), "action",
		    KATTRX_STRING, "briefs", "commit", KATTRX_STRING,
		    gw_trans->next_id, NULL);
		if (href_next == NULL) {
			error = got_error_from_errno("khttp_urlpartx");
			goto done;
		}
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A,
		    KATTR_HREF, href_next, KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req, "Next");
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 3);
		if (kerr != KCGI_OK)
			goto done;
	}

	if (gw_trans->next_id || gw_trans->page > 0) {
		kerr = khtml_closeelem(gw_trans->gw_html_req, 2);
		if (kerr != KCGI_OK)
			goto done;
	}
done:
	gw_free_header(header);
	TAILQ_FOREACH(n_header, &gw_trans->gw_headers, entry)
		gw_free_header(n_header);
	free(age);
	free(href_next);
	free(href_prev);
	free(href_diff);
	free(href_tree);
	if (error == NULL && kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
	return error;
}

static const struct got_error *
gw_summary(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	char *age = NULL;
	enum kcgi_err kerr = KCGI_OK;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath proc exec sendfd unveil",
	    NULL) == -1)
		return got_error_from_errno("pledge");
#endif
	error = gw_apply_unveil(gw_trans->gw_dir->path);
	if (error)
		goto done;

	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
	    "summary_wrapper", KATTR__MAX);
	if (kerr != KCGI_OK)
		return gw_kcgi_error(kerr);

	if (gw_trans->gw_conf->got_show_repo_description &&
	    gw_trans->gw_dir->description != NULL &&
	    (strcmp(gw_trans->gw_dir->description, "") != 0)) {
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "description_title", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req, "Description: ");
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "description", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req,
		    gw_trans->gw_dir->description);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;
	}

	if (gw_trans->gw_conf->got_show_repo_owner &&
	    gw_trans->gw_dir->owner != NULL &&
	    (strcmp(gw_trans->gw_dir->owner, "") != 0)) {
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "repo_owner_title", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req, "Owner: ");
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "repo_owner", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req,
		    gw_trans->gw_dir->owner);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;
	}

	if (gw_trans->gw_conf->got_show_repo_age) {
		error = gw_get_repo_age(&age, gw_trans, gw_trans->gw_dir->path,
		    NULL, TM_LONG);
		if (error)
			goto done;
		if (age != NULL) {
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "last_change_title", KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_puts(gw_trans->gw_html_req,
			    "Last Change: ");
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "last_change", KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_puts(gw_trans->gw_html_req, age);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
			if (kerr != KCGI_OK)
				goto done;
		}
	}

	if (gw_trans->gw_conf->got_show_repo_cloneurl &&
	    gw_trans->gw_dir->url != NULL &&
	    (strcmp(gw_trans->gw_dir->url, "") != 0)) {
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "cloneurl_title", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req, "Clone URL: ");
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "cloneurl", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req, gw_trans->gw_dir->url);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;
	}

	kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
	if (kerr != KCGI_OK)
		goto done;

	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
	    "briefs_title_wrapper", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
	    "briefs_title", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_puts(gw_trans->gw_html_req, "Commit Briefs");
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_closeelem(gw_trans->gw_html_req, 2);
	if (kerr != KCGI_OK)
		goto done;
	error = gw_briefs(gw_trans);
	if (error)
		goto done;

	error = gw_tags(gw_trans);
	if (error)
		goto done;

	error = gw_output_repo_heads(gw_trans);
done:
	free(age);
	if (error == NULL && kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
	return error;
}

static const struct got_error *
gw_tree(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	struct gw_header *header = NULL;
	char *tree = NULL, *tree_html = NULL, *tree_html_disp = NULL;
	char *age = NULL;
	enum kcgi_err kerr = KCGI_OK;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath proc exec sendfd unveil",
	    NULL) == -1)
		return got_error_from_errno("pledge");
#endif
	if ((header = gw_init_header()) == NULL)
		return got_error_from_errno("malloc");

	error = gw_apply_unveil(gw_trans->gw_dir->path);
	if (error)
		goto done;

	error = gw_get_header(gw_trans, header, 1);
	if (error)
		goto done;

	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
	    "tree_header_wrapper", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
	    "tree_header", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	error = gw_gen_tree_header(gw_trans, header->tree_id);
	if (error)
		goto done;
	error = gw_get_time_str(&age, header->committer_time,
	    TM_LONG);
	if (error)
		goto done;
	error = gw_gen_age_header(gw_trans, age ?age : "");
	if (error)
		goto done;
	error = gw_gen_commit_msg_header(gw_trans, header->commit_msg);
	if (error)
		goto done;
	kerr = khtml_closeelem(gw_trans->gw_html_req, 2);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
	    "dotted_line", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
	if (kerr != KCGI_OK)
		goto done;

	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
	    "tree", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	error = gw_output_repo_tree(gw_trans, header);
	if (error)
		goto done;

	kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
done:
	gw_free_header(header);
	free(tree_html_disp);
	free(tree_html);
	free(tree);
	free(age);
	if (error == NULL && kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
	return error;
}

static const struct got_error *
gw_tags(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	struct gw_header *header = NULL;
	char *href_next = NULL, *href_prev = NULL;
	enum kcgi_err kerr = KCGI_OK;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath proc exec sendfd unveil",
	    NULL) == -1)
		return got_error_from_errno("pledge");
#endif
	if ((header = gw_init_header()) == NULL)
		return got_error_from_errno("malloc");

	if (gw_trans->action != GW_SUMMARY) {
		error = gw_apply_unveil(gw_trans->gw_dir->path);
		if (error)
			goto done;
	}

	error = gw_get_header(gw_trans, header, 1);
	if (error)
		goto done;

	if (gw_trans->action == GW_SUMMARY) {
		gw_trans->next_id = NULL;
		error = gw_output_repo_tags(gw_trans, header,
		    D_MAXSLCOMMDISP, TAGBRIEF);
		if (error)
			goto done;
	} else {
		error = gw_output_repo_tags(gw_trans, header,
		    gw_trans->gw_conf->got_max_commits_display, TAGBRIEF);
		if (error)
			goto done;
	}

	if (gw_trans->next_id || gw_trans->page > 0) {
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "np_wrapper", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "nav_prev", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
	}

	if (gw_trans->prev_id) {
		href_prev = khttp_urlpartx(NULL, NULL, "gotweb", "path",
		    KATTRX_STRING, gw_trans->repo_name, "page",
		    KATTRX_INT, (int64_t) (gw_trans->page - 1), "action",
		    KATTRX_STRING, "tags", "commit", KATTRX_STRING,
		    gw_trans->prev_id ? gw_trans->prev_id : "", NULL);
		if (href_prev == NULL) {
			error = got_error_from_errno("khttp_urlpartx");
			goto done;
		}
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A,
		    KATTR_HREF, href_prev, KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req, "Previous");
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;
	}

	if (gw_trans->next_id || gw_trans->page > 0) {
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			return gw_kcgi_error(kerr);
	}

	if (gw_trans->next_id) {
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "nav_next", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		href_next = khttp_urlpartx(NULL, NULL, "gotweb", "path",
		    KATTRX_STRING, gw_trans->repo_name, "page",
		    KATTRX_INT, (int64_t) (gw_trans->page + 1), "action",
		    KATTRX_STRING, "tags", "commit", KATTRX_STRING,
		    gw_trans->next_id, NULL);
		if (href_next == NULL) {
			error = got_error_from_errno("khttp_urlpartx");
			goto done;
		}
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A,
		    KATTR_HREF, href_next, KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req, "Next");
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 3);
		if (kerr != KCGI_OK)
			goto done;
	}

	if (gw_trans->next_id || gw_trans->page > 0) {
		kerr = khtml_closeelem(gw_trans->gw_html_req, 2);
		if (kerr != KCGI_OK)
			goto done;
	}
done:
	gw_free_header(header);
	free(href_next);
	free(href_prev);
	if (error == NULL && kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
	return error;
}

static const struct got_error *
gw_tag(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	struct gw_header *header = NULL;
	enum kcgi_err kerr = KCGI_OK;

#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath proc exec sendfd unveil", NULL) == -1)
		return got_error_from_errno("pledge");
#endif
	if ((header = gw_init_header()) == NULL)
		return got_error_from_errno("malloc");

	error = gw_apply_unveil(gw_trans->gw_dir->path);
	if (error)
		goto done;

	if (gw_trans->commit_id == NULL) {
		error = got_error_msg(GOT_ERR_QUERYSTRING,
		    "commit required in querystring");
		goto done;
	}

	error = gw_get_header(gw_trans, header, 1);
	if (error)
		goto done;

	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
	    "tag_header_wrapper", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
	    "tag_header", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	error = gw_gen_commit_header(gw_trans, header->commit_id,
	    header->refs_str);
	if (error)
		goto done;
	error = gw_gen_commit_msg_header(gw_trans, header->commit_msg);
	if (error)
		goto done;
	kerr = khtml_closeelem(gw_trans->gw_html_req, 2);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
	    "dotted_line", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
	if (kerr != KCGI_OK)
		goto done;

	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
	    "tree", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;

	error = gw_output_repo_tags(gw_trans, header, 1, TAGFULL);
	if (error)
		goto done;

	kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
done:
	gw_free_header(header);
	if (error == NULL && kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
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
		if (gw_dir->path == NULL) {
			opened = 1;
			error = got_error_from_errno("strdup");
			goto errored;
		}
		opened = 1;
		goto done;
	}

	if (asprintf(&dir_test, "%s/%s/%s",
	    gw_trans->gw_conf->got_repos_path, gw_dir->name,
	    GOTWEB_GOT_DIR) == -1) {
		dir_test = NULL;
		error = got_error_from_errno("asprintf");
		goto errored;
	}

	dt = opendir(dir_test);
	if (dt == NULL)
		free(dir_test);
	else {
		opened = 1;
		error = got_error(GOT_ERR_NOT_GIT_REPO);
		goto errored;
	}

	if (asprintf(&dir_test, "%s/%s",
	    gw_trans->gw_conf->got_repos_path, gw_dir->name) == -1) {
		error = got_error_from_errno("asprintf");
		dir_test = NULL;
		goto errored;
	}

	gw_dir->path = strdup(dir_test);
	if (gw_dir->path == NULL) {
		opened = 1;
		error = got_error_from_errno("strdup");
		goto errored;
	}

	dt = opendir(dir_test);
	if (dt == NULL) {
		error = got_error_path(gw_dir->name, GOT_ERR_NOT_GIT_REPO);
		goto errored;
	} else
		opened = 1;
done:
	error = gw_get_repo_description(&gw_dir->description, gw_trans,
	    gw_dir->path);
	if (error)
		goto errored;
	error = gw_get_repo_owner(&gw_dir->owner, gw_trans, gw_dir->path);
	if (error)
		goto errored;
	error = gw_get_repo_age(&gw_dir->age, gw_trans, gw_dir->path,
	    NULL, TM_DIFF);
	if (error)
		goto errored;
	error = gw_get_clone_url(&gw_dir->url, gw_trans, gw_dir->path);
errored:
	free(dir_test);
	if (opened)
		if (dt && closedir(dt) == -1 && error == NULL)
			error = got_error_from_errno("closedir");
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
		goto done;
	}

	for (d_i = 0; d_i < d_cnt; d_i++) {
		if (gw_trans->gw_conf->got_max_repos > 0 &&
		    (d_i - 2) == gw_trans->gw_conf->got_max_repos)
			break; /* account for parent and self */

		if (strcmp(sd_dent[d_i]->d_name, ".") == 0 ||
		    strcmp(sd_dent[d_i]->d_name, "..") == 0)
			continue;

		error = gw_init_gw_dir(&gw_dir, sd_dent[d_i]->d_name);
		if (error)
			goto done;

		error = gw_load_got_path(gw_trans, gw_dir);
		if (error && error->code == GOT_ERR_NOT_GIT_REPO) {
			error = NULL;
			continue;
		} else if (error && error->code != GOT_ERR_LONELY_PACKIDX)
			goto done;

		if (lstat(gw_dir->path, &st) == 0 && S_ISDIR(st.st_mode) &&
		    !got_path_dir_is_empty(gw_dir->path)) {
			TAILQ_INSERT_TAIL(&gw_trans->gw_dirs, gw_dir,
			    entry);
			gw_trans->repos_total++;
		}
	}
done:
	if (d && closedir(d) == -1 && error == NULL)
		error = got_error_from_errno("closedir");
	return error;
}

static const struct got_error *
gw_parse_querystring(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	struct kpair *p;
	const struct gw_query_action *action = NULL;
	unsigned int i;

	if (gw_trans->gw_req->fieldnmap[0]) {
		return got_error(GOT_ERR_QUERYSTRING);
	} else if ((p = gw_trans->gw_req->fieldmap[KEY_PATH])) {
		/* define gw_trans->repo_path */
		gw_trans->repo_name = p->parsed.s;

		if (asprintf(&gw_trans->repo_path, "%s/%s",
		    gw_trans->gw_conf->got_repos_path, p->parsed.s) == -1)
			return got_error_from_errno("asprintf");

		/* get action and set function */
		if ((p = gw_trans->gw_req->fieldmap[KEY_ACTION])) {
			for (i = 0; i < nitems(gw_query_funcs); i++) {
				action = &gw_query_funcs[i];
				if (action->func_name == NULL)
					continue;
				if (strcmp(action->func_name,
				    p->parsed.s) == 0) {
					gw_trans->action = i;
					break;
				}
			}
		}
		if (gw_trans->action == -1) {
			gw_trans->action = GW_ERR;
			gw_trans->error = got_error_msg(GOT_ERR_QUERYSTRING,
			    p != NULL ? "bad action in querystring" :
			    "no action in querystring");
			return error;
		}

		if ((p = gw_trans->gw_req->fieldmap[KEY_COMMIT_ID])) {
			if (asprintf(&gw_trans->commit_id, "%s",
			    p->parsed.s) == -1)
				return got_error_from_errno("asprintf");
		}

		if ((p = gw_trans->gw_req->fieldmap[KEY_FILE]))
			gw_trans->repo_file = p->parsed.s;

		if ((p = gw_trans->gw_req->fieldmap[KEY_FOLDER])) {
			if (asprintf(&gw_trans->repo_folder, "%s",
			    p->parsed.s) == -1)
				return got_error_from_errno("asprintf");
		}

		if ((p = gw_trans->gw_req->fieldmap[KEY_PREV_ID])) {
			if (asprintf(&gw_trans->prev_id, "%s",
			    p->parsed.s) == -1)
				return got_error_from_errno("asprintf");
		}

		if ((p = gw_trans->gw_req->fieldmap[KEY_HEADREF]))
			gw_trans->headref = p->parsed.s;

		error = gw_init_gw_dir(&gw_trans->gw_dir, gw_trans->repo_name);
		if (error)
			return error;

		gw_trans->error = gw_load_got_path(gw_trans, gw_trans->gw_dir);
	} else
		gw_trans->action = GW_INDEX;

	if ((p = gw_trans->gw_req->fieldmap[KEY_PAGE]))
		gw_trans->page = p->parsed.i;

	return error;
}

static const struct got_error *
gw_init_gw_dir(struct gw_dir **gw_dir, const char *dir)
{
	const struct got_error *error;

	*gw_dir = malloc(sizeof(**gw_dir));
	if (*gw_dir == NULL)
		return got_error_from_errno("malloc");

	if (asprintf(&(*gw_dir)->name, "%s", dir) == -1) {
		error = got_error_from_errno("asprintf");
		free(*gw_dir);
		*gw_dir = NULL;
		return error;
	}

	return NULL;
}

static const struct got_error *
gw_display_open(struct gw_trans *gw_trans, enum khttp code, enum kmime mime)
{
	enum kcgi_err kerr = KCGI_OK;

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
	enum kcgi_err kerr = KCGI_OK;

	/* catch early querystring errors */
	if (gw_trans->error)
		gw_trans->action = GW_ERR;

	error = gw_display_open(gw_trans, KHTTP_200, gw_trans->mime);
	if (error)
		return error;

	kerr = khtml_open(gw_trans->gw_html_req, gw_trans->gw_req, 0);
	if (kerr != KCGI_OK)
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

static const struct got_error *
gw_error(struct gw_trans *gw_trans)
{
	enum kcgi_err kerr = KCGI_OK;

	kerr = khtml_puts(gw_trans->gw_html_req, gw_trans->error->msg);

	return gw_kcgi_error(kerr);
}

static int
gw_template(size_t key, void *arg)
{
	const struct got_error *error = NULL;
	enum kcgi_err kerr = KCGI_OK;
	struct gw_trans *gw_trans = arg;
	char *ati = NULL, *fic32 = NULL, *fic16 = NULL;
	char *swm = NULL, *spt = NULL, *css = NULL, *logo = NULL;

	if (asprintf(&ati, "%s%s", gw_trans->gw_conf->got_www_path,
	    "/apple-touch-icon.png") == -1)
		goto err;
	if (asprintf(&fic32, "%s%s", gw_trans->gw_conf->got_www_path,
	    "/favicon-32x32.png") == -1)
		goto err;
	if (asprintf(&fic16, "%s%s", gw_trans->gw_conf->got_www_path,
	    "/favicon-16x16.png") == -1)
		goto err;
	if (asprintf(&swm, "%s%s", gw_trans->gw_conf->got_www_path,
	    "/site.webmanifest") == -1)
		goto err;
	if (asprintf(&spt, "%s%s", gw_trans->gw_conf->got_www_path,
	    "/safari-pinned-tab.svg") == -1)
		goto err;
	if (asprintf(&css, "%s%s", gw_trans->gw_conf->got_www_path,
	    "/gotweb.css") == -1)
		goto err;
	if (asprintf(&logo, "%s%s%s", gw_trans->gw_conf->got_www_path,
	    gw_trans->gw_conf->got_www_path ? "/" : "",
	    gw_trans->gw_conf->got_logo) == -1)
		goto err;

	switch (key) {
	case (TEMPL_HEAD):
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_META,
		    KATTR_NAME, "viewport",
		    KATTR_CONTENT, "initial-scale=.75, user-scalable=yes",
		    KATTR__MAX);
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_META,
		    KATTR_CHARSET, "utf-8",
		    KATTR__MAX);
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_META,
		    KATTR_NAME, "msapplication-TileColor",
		    KATTR_CONTENT, "#da532c", KATTR__MAX);
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_META,
		    KATTR_NAME, "theme-color",
		    KATTR_CONTENT, "#ffffff", KATTR__MAX);
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_LINK,
		    KATTR_REL, "apple-touch-icon", KATTR_SIZES, "180x180",
		    KATTR_HREF, ati, KATTR__MAX);
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_LINK,
		    KATTR_REL, "icon", KATTR_TYPE, "image/png", KATTR_SIZES,
		    "32x32", KATTR_HREF, fic32, KATTR__MAX);
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_LINK,
		    KATTR_REL, "icon", KATTR_TYPE, "image/png", KATTR_SIZES,
		    "16x16", KATTR_HREF, fic16, KATTR__MAX);
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_LINK,
		    KATTR_REL, "manifest", KATTR_HREF, swm,
		    KATTR__MAX);
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_LINK,
		    KATTR_REL, "mask-icon", KATTR_HREF,
		    spt, KATTR__MAX);
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_LINK,
		    KATTR_REL, "stylesheet", KATTR_TYPE, "text/css",
		    KATTR_HREF, css, KATTR__MAX);
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			return 0;
		break;
	case(TEMPL_HEADER):
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "got_link", KATTR__MAX);
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A,
		    KATTR_HREF,  gw_trans->gw_conf->got_logo_url,
		    KATTR_TARGET, "_sotd", KATTR__MAX);
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_IMG,
		    KATTR_SRC, logo, KATTR__MAX);
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 3);
		if (kerr != KCGI_OK)
			return 0;
		break;
	case (TEMPL_SITEPATH):
		error = gw_output_site_link(gw_trans);
		if (error)
			return 0;
		break;
	case(TEMPL_TITLE):
		if (gw_trans->gw_conf->got_site_name != NULL) {
			kerr = khtml_puts(gw_trans->gw_html_req,
			    gw_trans->gw_conf->got_site_name);
			if (kerr != KCGI_OK)
				return 0;
		}
		break;
	case (TEMPL_SEARCH):
		break;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "search", KATTR__MAX);
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_FORM,
			    KATTR_METHOD, "POST", KATTR__MAX);
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_INPUT, KATTR_ID,
		    "got-search", KATTR_NAME, "got-search", KATTR_SIZE, "15",
		    KATTR_MAXLENGTH, "50", KATTR__MAX);
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_BUTTON,
		    KATTR__MAX);
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_puts(gw_trans->gw_html_req, "Search");
		if (kerr != KCGI_OK)
			return 0;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 4);
		if (kerr != KCGI_OK)
			return 0;
		break;
	case(TEMPL_SITEOWNER):
		if (gw_trans->gw_conf->got_site_owner != NULL &&
		    gw_trans->gw_conf->got_show_site_owner) {
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "site_owner_wrapper", KATTR__MAX);
			if (kerr != KCGI_OK)
				return 0;
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "site_owner", KATTR__MAX);
			if (kerr != KCGI_OK)
				return 0;
			kerr = khtml_puts(gw_trans->gw_html_req,
			    gw_trans->gw_conf->got_site_owner);
			kerr = khtml_closeelem(gw_trans->gw_html_req, 2);
			if (kerr != KCGI_OK)
				return 0;
		}
		break;
	case(TEMPL_CONTENT):
		error = gw_query_funcs[gw_trans->action].func_main(gw_trans);
		if (error) {
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "tmpl_err", KATTR__MAX);
			if (kerr != KCGI_OK)
				return 0;
			kerr = khttp_printf(gw_trans->gw_req, "Error: %s",
			    error->msg);
			if (kerr != KCGI_OK)
				return 0;
			kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
			if (kerr != KCGI_OK)
				return 0;
		}
		break;
	default:
		return 0;
	}
	free(ati);
	free(fic32);
	free(fic16);
	free(swm);
	free(spt);
	free(css);
	free(logo);
	return 1;
err:
	free(ati);
	free(fic32);
	free(fic16);
	free(swm);
	free(spt);
	free(css);
	free(logo);
	return 0;
}

static const struct got_error *
gw_gen_commit_header(struct gw_trans *gw_trans, char *str1, char *str2)
{
	const struct got_error *error = NULL;
	enum kcgi_err kerr = KCGI_OK;

	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
	    KATTR_ID, "header_commit_title", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_puts(gw_trans->gw_html_req, "Commit: ");
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
	    KATTR_ID, "header_commit", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_printf(gw_trans->gw_html_req, "%s ", str1);
	if (kerr != KCGI_OK)
		goto done;
	if (str2 != NULL) {
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_SPAN,
		    KATTR_ID, "refs_str", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_printf(gw_trans->gw_html_req, "(%s)", str2);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;
	}
	kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
done:
	if (error == NULL && kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
	return error;
}

static const struct got_error *
gw_gen_diff_header(struct gw_trans *gw_trans, char *str1, char *str2)
{
	const struct got_error *error = NULL;
	enum kcgi_err kerr = KCGI_OK;

	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
	    KATTR_ID, "header_diff_title", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_puts(gw_trans->gw_html_req, "Diff: ");
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
	    KATTR_ID, "header_diff", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	if (str1 != NULL) {
		kerr = khtml_puts(gw_trans->gw_html_req, str1);
		if (kerr != KCGI_OK)
			goto done;
	}
	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_BR, KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_puts(gw_trans->gw_html_req, str2);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
done:
	if (error == NULL && kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
	return error;
}

static const struct got_error *
gw_gen_age_header(struct gw_trans *gw_trans, const char *str)
{
	const struct got_error *error = NULL;
	enum kcgi_err kerr = KCGI_OK;

	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
	    KATTR_ID, "header_age_title", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_puts(gw_trans->gw_html_req, "Date: ");
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
	    KATTR_ID, "header_age", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_puts(gw_trans->gw_html_req, str);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
done:
	if (error == NULL && kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
	return error;
}

static const struct got_error *
gw_gen_author_header(struct gw_trans *gw_trans, const char *str)
{
	const struct got_error *error = NULL;
	enum kcgi_err kerr = KCGI_OK;

	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
	    KATTR_ID, "header_author_title", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_puts(gw_trans->gw_html_req, "Author: ");
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
	    KATTR_ID, "header_author", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_puts(gw_trans->gw_html_req, str);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
done:
	if (error == NULL && kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
	return error;
}

static const struct got_error *
gw_gen_committer_header(struct gw_trans *gw_trans, const char *str)
{
	const struct got_error *error = NULL;
	enum kcgi_err kerr = KCGI_OK;

	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
	    KATTR_ID, "header_committer_title", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_puts(gw_trans->gw_html_req, "Committer: ");
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
	    KATTR_ID, "header_committer", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_puts(gw_trans->gw_html_req, str);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
done:
	if (error == NULL && kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
	return error;
}

static const struct got_error *
gw_gen_commit_msg_header(struct gw_trans *gw_trans, char *str)
{
	const struct got_error *error = NULL;
	enum kcgi_err kerr = KCGI_OK;

	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
	    KATTR_ID, "header_commit_msg_title", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_puts(gw_trans->gw_html_req, "Message: ");
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
	    KATTR_ID, "header_commit_msg", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khttp_puts(gw_trans->gw_req, str);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
done:
	if (error == NULL && kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
	return error;
}

static const struct got_error *
gw_gen_tree_header(struct gw_trans *gw_trans, char *str)
{
	const struct got_error *error = NULL;
	enum kcgi_err kerr = KCGI_OK;

	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
	    KATTR_ID, "header_tree_title", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_puts(gw_trans->gw_html_req, "Tree: ");
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
	    KATTR_ID, "header_tree", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_puts(gw_trans->gw_html_req, str);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
done:
	if (error == NULL && kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
	return error;
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
		return NULL;

	if (asprintf(&d_file, "%s/description", dir) == -1)
		return got_error_from_errno("asprintf");

	f = fopen(d_file, "re");
	if (f == NULL) {
		if (errno == ENOENT || errno == EACCES)
			return NULL;
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
	if (f != NULL && fclose(f) == EOF && error == NULL)
		error = got_error_from_errno("fclose");
	free(d_file);
	return error;
}

static const struct got_error *
gw_get_time_str(char **repo_age, time_t committer_time, int ref_tm)
{
	struct tm tm;
	time_t diff_time;
	const char *years = "years ago", *months = "months ago";
	const char *weeks = "weeks ago", *days = "days ago", *hours = "hours ago";
	const char *minutes = "minutes ago", *seconds = "seconds ago";
	const char *now = "right now";
	const char *s;
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
    const char *refname, int ref_tm)
{
	const struct got_error *error = NULL;
	struct got_repository *repo = NULL;
	struct got_commit_object *commit = NULL;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;
	time_t committer_time = 0, cmp_time = 0;

	*repo_age = NULL;
	TAILQ_INIT(&refs);

	if (gw_trans->gw_conf->got_show_repo_age == 0)
		return NULL;

	if (gw_trans->repo)
		repo = gw_trans->repo;
	else {
		error = got_repo_open(&repo, dir, NULL, gw_trans->pack_fds);
		if (error)
			return error;
	}

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
		error = gw_get_time_str(repo_age, committer_time, ref_tm);
	}
done:
	got_ref_list_free(&refs);
	if (gw_trans->repo == NULL) {
		const struct got_error *close_err = got_repo_close(repo);
		if (error == NULL)
			error = close_err;
	}
	return error;
}

static const struct got_error *
gw_output_diff(struct gw_trans *gw_trans, struct gw_header *header)
{
	const struct got_error *error;
	FILE *f = NULL, *f1 = NULL, *f2 = NULL;
	int fd1 = -1, fd2 = -1;
	struct got_object_id *id1 = NULL, *id2 = NULL;
	char *label1 = NULL, *label2 = NULL, *line = NULL;
	int obj_type;
	size_t linesize = 0;
	ssize_t linelen;
	enum kcgi_err kerr = KCGI_OK;

	f = got_opentemp();
	if (f == NULL)
		return NULL;

	f1 = got_opentemp();
	if (f1 == NULL) {
		error = got_error_from_errno("got_opentemp");
		goto done;
	}

	f2 = got_opentemp();
	if (f2 == NULL) {
		error = got_error_from_errno("got_opentemp");
		goto done;
	}

	fd1 = got_opentempfd();
	if (fd1 == -1) {
		error = got_error_from_errno("got_opentempfd");
		goto done;
	}

	fd2 = got_opentempfd();
	if (fd2 == -1) {
		error = got_error_from_errno("got_opentempfd");
		goto done;
	}

	if (header->parent_id != NULL &&
	    strncmp(header->parent_id, "/dev/null", 9) != 0) {
		error = got_repo_match_object_id(&id1, &label1,
			header->parent_id, GOT_OBJ_TYPE_ANY,
			&header->refs, gw_trans->repo);
		if (error)
			goto done;
	}

	error = got_repo_match_object_id(&id2, &label2,
	    header->commit_id, GOT_OBJ_TYPE_ANY, &header->refs,
	    gw_trans->repo);
	if (error)
		goto done;

	error = got_object_get_type(&obj_type, gw_trans->repo, id2);
	if (error)
		goto done;
	switch (obj_type) {
	case GOT_OBJ_TYPE_BLOB:
		error = got_diff_objects_as_blobs(NULL, NULL, f1, f2,
		    fd1, fd2, id1, id2, NULL, NULL, GOT_DIFF_ALGORITHM_PATIENCE,
		    3, 0, 0, gw_trans->repo, f);
		break;
	case GOT_OBJ_TYPE_TREE:
		error = got_diff_objects_as_trees(NULL, NULL, f1, f2,
		    fd1, fd2, id1, id2, NULL, "", "",
		    GOT_DIFF_ALGORITHM_PATIENCE, 3, 0, 0, gw_trans->repo, f);
		break;
	case GOT_OBJ_TYPE_COMMIT:
		error = got_diff_objects_as_commits(NULL, NULL, f1, f2,
		    fd1, fd2, id1, id2, NULL, GOT_DIFF_ALGORITHM_PATIENCE,
		    3, 0, 0, gw_trans->repo, f);
		break;
	default:
		error = got_error(GOT_ERR_OBJ_TYPE);
	}
	if (error)
		goto done;

	if (fseek(f, 0, SEEK_SET) == -1) {
		error = got_ferror(f, GOT_ERR_IO);
		goto done;
	}

	while ((linelen = getline(&line, &linesize, f)) != -1) {
		error = gw_colordiff_line(gw_trans, line);
		if (error)
			goto done;
		/* XXX: KHTML_PRETTY breaks this */
		kerr = khtml_puts(gw_trans->gw_html_req, line);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;
	}
	if (linelen == -1 && ferror(f))
		error = got_error_from_errno("getline");
done:
	if (f && fclose(f) == EOF && error == NULL)
		error = got_error_from_errno("fclose");
	if (f1 && fclose(f1) == EOF && error == NULL)
		error = got_error_from_errno("fclose");
	if (f2 && fclose(f2) == EOF && error == NULL)
		error = got_error_from_errno("fclose");
	if (fd1 != -1 && close(fd1) == -1 && error == NULL)
		error = got_error_from_errno("close");
	if (fd2 != -1 && close(fd2) == -1 && error == NULL)
		error = got_error_from_errno("close");
	free(line);
	free(label1);
	free(label2);
	free(id1);
	free(id2);

	if (error == NULL && kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
	return error;
}

static const struct got_error *
gw_get_repo_owner(char **owner, struct gw_trans *gw_trans, char *dir)
{
	const struct got_error *error = NULL, *close_err;
	struct got_repository *repo;
	const char *gitconfig_owner;

	*owner = NULL;

	if (gw_trans->gw_conf->got_show_repo_owner == 0)
		return NULL;

	error = got_repo_open(&repo, dir, NULL, gw_trans->pack_fds);
	if (error)
		return error;

	gitconfig_owner = got_repo_get_gitconfig_owner(repo);
	if (gitconfig_owner) {
		*owner = strdup(gitconfig_owner);
		if (*owner == NULL)
			error = got_error_from_errno("strdup");
	}
	close_err = got_repo_close(repo);
	if (error == NULL)
		error = close_err;
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

	f = fopen(d_file, "re");
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
	if (f && fclose(f) == EOF && error == NULL)
		error = got_error_from_errno("fclose");
	free(d_file);
	return NULL;
}

static const struct got_error *
gw_output_repo_tags(struct gw_trans *gw_trans, struct gw_header *header,
    int limit, int tag_type)
{
	const struct got_error *error = NULL;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;
	char *age = NULL;
	char *id_str = NULL, *newline, *href_commits = NULL;
	char *tag_commit0 = NULL, *href_tag = NULL, *href_briefs = NULL;
	struct got_tag_object *tag = NULL;
	enum kcgi_err kerr = KCGI_OK;
	int summary_header_displayed = 0, chk_next = 0;
	int tag_count = 0, commit_found = 0, c_cnt = 0;

	TAILQ_INIT(&refs);

	error = got_ref_list(&refs, gw_trans->repo, "refs/tags",
	    got_ref_cmp_tags, gw_trans->repo);
	if (error)
		goto done;

	TAILQ_FOREACH(re, &refs, entry) {
		const char *refname;
		const char *tagger;
		const char *tag_commit;
		time_t tagger_time;
		struct got_object_id *id;
		struct got_commit_object *commit = NULL;

		refname = got_ref_get_name(re->ref);
		if (strncmp(refname, "refs/tags/", 10) != 0)
			continue;
		refname += 10;

		error = got_ref_resolve(&id, gw_trans->repo, re->ref);
		if (error)
			goto done;

		error = got_object_open_as_tag(&tag, gw_trans->repo, id);
		if (error) {
			if (error->code != GOT_ERR_OBJ_TYPE) {
				free(id);
				goto done;
			}
			/* "lightweight" tag */
			error = got_object_open_as_commit(&commit,
			    gw_trans->repo, id);
			if (error) {
				free(id);
				goto done;
			}
			tagger = got_object_commit_get_committer(commit);
			tagger_time =
			    got_object_commit_get_committer_time(commit);
			error = got_object_id_str(&id_str, id);
			free(id);
		} else {
			free(id);
			tagger = got_object_tag_get_tagger(tag);
			tagger_time = got_object_tag_get_tagger_time(tag);
			error = got_object_id_str(&id_str,
			    got_object_tag_get_object_id(tag));
		}
		if (error)
			goto done;

		if (tag_type == TAGFULL && strncmp(id_str, header->commit_id,
		    strlen(id_str)) != 0)
			continue;

		if (tag_type == TAGBRIEF && gw_trans->commit_id &&
		    commit_found == 0 && strncmp(id_str, gw_trans->commit_id,
		    strlen(id_str)) != 0)
			continue;
		else
			commit_found = 1;

		tag_count++;

		if (chk_next) {
			gw_trans->next_id = strdup(id_str);
			if (gw_trans->next_id == NULL)
				error = got_error_from_errno("strdup");
			goto prev;
		}

		if (commit) {
			error = got_object_commit_get_logmsg(&tag_commit0,
			    commit);
			if (error)
				goto done;
			got_object_commit_close(commit);
		} else {
			tag_commit0 = strdup(got_object_tag_get_message(tag));
			if (tag_commit0 == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
		}

		tag_commit = tag_commit0;
		while (*tag_commit == '\n')
			tag_commit++;

		switch (tag_type) {
		case TAGBRIEF:
			newline = strchr(tag_commit, '\n');
			if (newline)
				*newline = '\0';

			if (summary_header_displayed == 0) {
				kerr = khtml_attr(gw_trans->gw_html_req,
				    KELEM_DIV, KATTR_ID,
				    "summary_tags_title_wrapper", KATTR__MAX);
				if (kerr != KCGI_OK)
					goto done;
				kerr = khtml_attr(gw_trans->gw_html_req,
				    KELEM_DIV, KATTR_ID,
				    "summary_tags_title", KATTR__MAX);
				if (kerr != KCGI_OK)
					goto done;
				kerr = khtml_puts(gw_trans->gw_html_req,
				    "Tags");
				if (kerr != KCGI_OK)
					goto done;
				kerr = khtml_closeelem(gw_trans->gw_html_req,
				    2);
				if (kerr != KCGI_OK)
					goto done;
				kerr = khtml_attr(gw_trans->gw_html_req,
				    KELEM_DIV, KATTR_ID,
				    "summary_tags_content", KATTR__MAX);
				if (kerr != KCGI_OK)
					goto done;
				summary_header_displayed = 1;
			}

			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "tag_wrapper", KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "tag_age", KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			error = gw_get_time_str(&age, tagger_time, TM_DIFF);
			if (error)
				goto done;
			kerr = khtml_puts(gw_trans->gw_html_req,
			    age ? age : "");
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "tag", KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_puts(gw_trans->gw_html_req, refname);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "tag_name", KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;

			href_tag = khttp_urlpart(NULL, NULL, "gotweb", "path",
			    gw_trans->repo_name, "action", "tag", "commit",
			    id_str, NULL);
			if (href_tag == NULL) {
				error = got_error_from_errno("khttp_urlpart");
				goto done;
			}
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A,
			    KATTR_HREF, href_tag, KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_puts(gw_trans->gw_html_req, tag_commit);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_closeelem(gw_trans->gw_html_req, 3);
			if (kerr != KCGI_OK)
				goto done;

			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "navs_wrapper", KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "navs", KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;

			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A,
			    KATTR_HREF, href_tag, KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_puts(gw_trans->gw_html_req, "tag");
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
			if (kerr != KCGI_OK)
				goto done;

			kerr = khtml_puts(gw_trans->gw_html_req, " | ");
			if (kerr != KCGI_OK)
				goto done;

			href_briefs = khttp_urlpart(NULL, NULL, "gotweb",
			    "path", gw_trans->repo_name, "action", "briefs",
			    "commit", id_str, NULL);
			if (href_briefs == NULL) {
				error = got_error_from_errno("khttp_urlpart");
				goto done;
			}
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A,
			    KATTR_HREF, href_briefs, KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_puts(gw_trans->gw_html_req,
			    "commit briefs");
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
			if (kerr != KCGI_OK)
				goto done;

			kerr = khtml_puts(gw_trans->gw_html_req, " | ");
			if (kerr != KCGI_OK)
				goto done;

			href_commits = khttp_urlpart(NULL, NULL, "gotweb",
			    "path", gw_trans->repo_name, "action", "commits",
			    "commit", id_str, NULL);
			if (href_commits == NULL) {
				error = got_error_from_errno("khttp_urlpart");
				goto done;
			}
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A,
			    KATTR_HREF, href_commits, KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_puts(gw_trans->gw_html_req, "commits");
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_closeelem(gw_trans->gw_html_req, 3);
			if (kerr != KCGI_OK)
				goto done;

			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "dotted_line", KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_closeelem(gw_trans->gw_html_req, 2);
			if (kerr != KCGI_OK)
				goto done;
			break;
		case TAGFULL:
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "tag_info_date_title", KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_puts(gw_trans->gw_html_req, "Tag Date:");
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "tag_info_date", KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			error = gw_get_time_str(&age, tagger_time, TM_LONG);
			if (error)
				goto done;
			kerr = khtml_puts(gw_trans->gw_html_req,
			    age ? age : "");
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
			if (kerr != KCGI_OK)
				goto done;

			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "tag_info_tagger_title", KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_puts(gw_trans->gw_html_req, "Tagger:");
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "tag_info_date", KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_puts(gw_trans->gw_html_req, tagger);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
			if (kerr != KCGI_OK)
				goto done;

			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "tag_info", KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khttp_puts(gw_trans->gw_req, tag_commit);
			if (kerr != KCGI_OK)
				goto done;
			break;
		default:
			break;
		}
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;

		if (limit && --limit == 0)
			chk_next = 1;

		if (tag)
			got_object_tag_close(tag);
		tag = NULL;
		free(id_str);
		id_str = NULL;
		free(age);
		age = NULL;
		free(tag_commit0);
		tag_commit0 = NULL;
		free(href_tag);
		href_tag = NULL;
		free(href_briefs);
		href_briefs = NULL;
		free(href_commits);
		href_commits = NULL;
	}
	if (tag_count == 0) {
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "summary_tags_title_wrapper", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "summary_tags_title", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req, "Tags");
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 2);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "summary_tags_content", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "tags_info", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khttp_puts(gw_trans->gw_req,
		    "There are no tags for this repo.");
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 2);
		goto done;
	}
prev:
	commit_found = 0;
	TAILQ_FOREACH_REVERSE(re, &refs, got_reflist_head, entry) {
		const char *refname;
		struct got_object_id *id;
		struct got_commit_object *commit = NULL;

		refname = got_ref_get_name(re->ref);
		if (strncmp(refname, "refs/tags/", 10) != 0)
			continue;
		refname += 10;

		error = got_ref_resolve(&id, gw_trans->repo, re->ref);
		if (error)
			goto done;

		error = got_object_open_as_tag(&tag, gw_trans->repo, id);
		if (error) {
			if (error->code != GOT_ERR_OBJ_TYPE) {
				free(id);
				goto done;
			}
			/* "lightweight" tag */
			error = got_object_open_as_commit(&commit,
			    gw_trans->repo, id);
			if (error) {
				free(id);
				goto done;
			}
			error = got_object_id_str(&id_str, id);
			free(id);
		} else {
			free(id);
			error = got_object_id_str(&id_str,
			    got_object_tag_get_object_id(tag));
		}
		if (error)
			goto done;

		if (tag_type == TAGFULL && strncmp(id_str, header->commit_id,
		    strlen(id_str)) != 0)
			continue;

		if (commit_found == 0 && tag_type == TAGBRIEF &&
		    gw_trans->commit_id  != NULL &&
		    strncmp(id_str, gw_trans->commit_id, strlen(id_str)) != 0)
			continue;
		else
			commit_found = 1;

		if (gw_trans->commit_id != NULL &&
		    strcmp(id_str, gw_trans->commit_id) != 0 &&
		    (re == TAILQ_FIRST(&refs) ||
		    c_cnt == gw_trans->gw_conf->got_max_commits_display)) {
			gw_trans->prev_id = strdup(id_str);
			if (gw_trans->prev_id == NULL) {
				error = got_error_from_errno("strdup");
				goto done;
			}
			break;
		}
		c_cnt++;
	}
done:
	if (tag)
		got_object_tag_close(tag);
	free(id_str);
	free(age);
	free(tag_commit0);
	free(href_tag);
	free(href_briefs);
	free(href_commits);
	got_ref_list_free(&refs);
	if (error == NULL && kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
	return error;
}

static void
gw_free_header(struct gw_header *header)
{
	free(header->path);
	free(header->author);
	free(header->committer);
	free(header->refs_str);
	free(header->commit_id);
	free(header->parent_id);
	free(header->tree_id);
	free(header->commit_msg);
}

static struct gw_header *
gw_init_header()
{
	struct gw_header *header;

	header = malloc(sizeof(*header));
	if (header == NULL)
		return NULL;

	header->path = NULL;
	TAILQ_INIT(&header->refs);

	header->refs_str = NULL;
	header->commit_id = NULL;
	header->committer = NULL;
	header->author = NULL;
	header->parent_id = NULL;
	header->tree_id = NULL;
	header->commit_msg = NULL;

	return header;
}

static const struct got_error *
gw_get_commits(struct gw_trans * gw_trans, struct gw_header *header,
    int limit, struct got_object_id *id)
{
	const struct got_error *error = NULL;
	struct got_commit_graph *graph = NULL;
	struct got_commit_object *commit = NULL;
	int chk_next = 0, chk_multi = 0, c_cnt = 0, commit_found = 0;
	struct gw_header *t_header = NULL;

	error = got_commit_graph_open(&graph, header->path, 0);
	if (error)
		return error;

	error = got_commit_graph_iter_start(graph, id, gw_trans->repo, NULL,
	    NULL);
	if (error)
		goto err;

	for (;;) {
		error = got_commit_graph_iter_next(&id, graph, gw_trans->repo,
		    NULL, NULL);
		if (error) {
			if (error->code == GOT_ERR_ITER_COMPLETED)
				error = NULL;
			goto done;
		}
		if (id == NULL)
			goto err;

		error = got_object_open_as_commit(&commit, gw_trans->repo, id);
		if (error)
			goto err;
		if (limit == 1 && chk_multi == 0 &&
		    gw_trans->gw_conf->got_max_commits_display != 1) {
			error = gw_get_commit(gw_trans, header, commit, id);
			if (error)
				goto err;
			commit_found = 1;
		} else {
			chk_multi = 1;
			struct gw_header *n_header = NULL;
			if ((n_header = gw_init_header()) == NULL) {
				error = got_error_from_errno("malloc");
				goto err;
			}
			TAILQ_INSERT_TAIL(&gw_trans->gw_headers, n_header,
			    entry);
			error = got_ref_list(&n_header->refs, gw_trans->repo,
			    NULL, got_ref_cmp_by_name, NULL);
			if (error)
				goto err;

			error = gw_get_commit(gw_trans, n_header, commit, id);
			if (error)
				goto err;
			got_ref_list_free(&n_header->refs);

			if (gw_trans->commit_id != NULL) {
				if (strcmp(gw_trans->commit_id,
				    n_header->commit_id) == 0)
					commit_found = 1;
			} else
				commit_found = 1;

			/*
			 * check for one more commit before breaking,
			 * so we know whether to navigate through gw_briefs
			 * gw_commits and gw_summary
			 */
			if (chk_next && (gw_trans->action == GW_BRIEFS ||
			    gw_trans->action == GW_COMMITS ||
			    gw_trans->action == GW_SUMMARY)) {
				gw_trans->next_id = strdup(n_header->commit_id);
				if (gw_trans->next_id == NULL)
					error = got_error_from_errno("strdup");
				TAILQ_REMOVE(&gw_trans->gw_headers, n_header,
				    entry);
				goto done;
			}

		}
		if (commit_found == 1 && (error || (limit && --limit == 0))) {
			if (chk_multi == 0)
				break;
			chk_next = 1;
		}
	}
done:
	if (gw_trans->prev_id == NULL && gw_trans->commit_id != NULL &&
	    (gw_trans->action == GW_BRIEFS || gw_trans->action == GW_COMMITS)) {
		commit_found = 0;
		TAILQ_FOREACH_REVERSE(t_header, &gw_trans->gw_headers,
		    headers, entry) {
			if (commit_found == 0 &&
			    strcmp(gw_trans->commit_id,
			    t_header->commit_id) != 0)
				continue;
			else
				commit_found = 1;
			if (gw_trans->commit_id != NULL &&
			    strcmp(gw_trans->commit_id,
			    t_header->commit_id) != 0 &&
			    (c_cnt == gw_trans->gw_conf->got_max_commits_display
			    || t_header ==
			    TAILQ_FIRST(&gw_trans->gw_headers))) {
				gw_trans->prev_id = strdup(t_header->commit_id);
				if (gw_trans->prev_id == NULL)
					error = got_error_from_errno("strdup");
				break;
			}
			c_cnt++;
		}
	}
err:
	if (commit != NULL)
		got_object_commit_close(commit);
	if (graph)
		got_commit_graph_close(graph);
	return error;
}

static const struct got_error *
gw_get_commit(struct gw_trans *gw_trans, struct gw_header *header,
    struct got_commit_object *commit, struct got_object_id *id)
{
	const struct got_error *error = NULL;
	struct got_reflist_entry *re;
	struct got_object_id *id2 = NULL;
	struct got_object_qid *parent_id;
	char *commit_msg = NULL, *commit_msg0;

	/*print commit*/
	TAILQ_FOREACH(re, &header->refs, entry) {
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
			s = strstr(name, "/" GOT_REF_HEAD);
			if (s != NULL && s[strlen(s)] == '\0')
				continue;
		}
		error = got_ref_resolve(&ref_id, gw_trans->repo, re->ref);
		if (error)
			return error;
		if (strncmp(name, "tags/", 5) == 0) {
			error = got_object_open_as_tag(&tag, gw_trans->repo,
			    ref_id);
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
		s = header->refs_str;
		if (asprintf(&header->refs_str, "%s%s%s", s ? s : "",
		    s ? ", " : "", name) == -1) {
			error = got_error_from_errno("asprintf");
			free(s);
			header->refs_str = NULL;
			return error;
		}
		free(s);
	}

	error = got_object_id_str(&header->commit_id, id);
	if (error)
		return error;

	error = got_object_id_str(&header->tree_id,
	    got_object_commit_get_tree_id(commit));
	if (error)
		return error;

	if (gw_trans->action == GW_DIFF) {
		parent_id = STAILQ_FIRST(
		    got_object_commit_get_parent_ids(commit));
		if (parent_id != NULL) {
			id2 = got_object_id_dup(&parent_id->id);
			free (parent_id);
			error = got_object_id_str(&header->parent_id, id2);
			if (error)
				return error;
			free(id2);
		} else {
			header->parent_id = strdup("/dev/null");
			if (header->parent_id == NULL) {
				error = got_error_from_errno("strdup");
				return error;
			}
		}
	}

	header->committer_time =
	    got_object_commit_get_committer_time(commit);

	header->author =
	    strdup(got_object_commit_get_author(commit));
	if (header->author == NULL) {
		error = got_error_from_errno("strdup");
		return error;
	}
	header->committer =
	    strdup(got_object_commit_get_committer(commit));
	if (header->committer == NULL) {
		error = got_error_from_errno("strdup");
		return error;
	}
	error = got_object_commit_get_logmsg(&commit_msg0, commit);
	if (error)
		return error;

	commit_msg = commit_msg0;
	while (*commit_msg == '\n')
		commit_msg++;

	header->commit_msg = strdup(commit_msg);
	if (header->commit_msg == NULL)
		error = got_error_from_errno("strdup");
	free(commit_msg0);
	return error;
}

static const struct got_error *
gw_get_header(struct gw_trans *gw_trans, struct gw_header *header, int limit)
{
	const struct got_error *error = NULL;
	char *in_repo_path = NULL;
	struct got_object_id *id = NULL;
	struct got_reference *ref;

	error = got_repo_open(&gw_trans->repo, gw_trans->repo_path, NULL,
	    gw_trans->pack_fds);
	if (error)
		return error;

	if (gw_trans->commit_id == NULL || gw_trans->action == GW_COMMITS ||
	    gw_trans->action == GW_BRIEFS || gw_trans->action == GW_SUMMARY ||
	    gw_trans->action == GW_TAGS) {
		error = got_ref_open(&ref, gw_trans->repo,
		    gw_trans->headref, 0);
		if (error)
			return error;

		error = got_ref_resolve(&id, gw_trans->repo, ref);
		got_ref_close(ref);
		if (error)
			return error;
	} else {
		error = got_ref_open(&ref, gw_trans->repo,
		    gw_trans->commit_id, 0);
		if (error == NULL) {
			int obj_type;
			error = got_ref_resolve(&id, gw_trans->repo, ref);
			got_ref_close(ref);
			if (error)
				return error;
			error = got_object_get_type(&obj_type, gw_trans->repo,
			    id);
			if (error)
				goto done;
			if (obj_type == GOT_OBJ_TYPE_TAG) {
				struct got_tag_object *tag;
				error = got_object_open_as_tag(&tag,
				    gw_trans->repo, id);
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
		error = got_repo_match_object_id_prefix(&id,
			    gw_trans->commit_id, GOT_OBJ_TYPE_COMMIT,
			    gw_trans->repo);
		if (error)
			goto done;
	}

	error = got_repo_map_path(&in_repo_path, gw_trans->repo,
	    gw_trans->repo_path);
	if (error)
		goto done;

	if (in_repo_path) {
		header->path = strdup(in_repo_path);
		if (header->path == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
	}

	error = got_ref_list(&header->refs, gw_trans->repo, NULL,
	    got_ref_cmp_by_name, NULL);
	if (error)
		goto done;

	error = gw_get_commits(gw_trans, header, limit, id);
done:
	free(id);
	free(in_repo_path);
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
};

static const struct got_error *
gw_blame_cb(void *arg, int nlines, int lineno,
    struct got_commit_object *commit, struct got_object_id *id)
{
	const struct got_error *err = NULL;
	struct gw_blame_cb_args *a = arg;
	struct blame_line *bline;
	char *line = NULL;
	size_t linesize = 0;
	off_t offset;
	struct tm tm;
	time_t committer_time;
	enum kcgi_err kerr = KCGI_OK;

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
		char *smallerthan, *at, *nl, *committer;
		char *href_diff = NULL;
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

		kerr = khtml_attr(a->gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "blame_wrapper", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto err;
		kerr = khtml_attr(a->gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "blame_number", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto err;
		kerr = khtml_printf(a->gw_trans->gw_html_req, "%.*d",
		    a->nlines_prec, a->lineno_cur);
		if (kerr != KCGI_OK)
			goto err;
		kerr = khtml_closeelem(a->gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto err;

		kerr = khtml_attr(a->gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "blame_hash", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto err;

		href_diff = khttp_urlpart(NULL, NULL, "gotweb", "path",
		    a->gw_trans->repo_name, "action", "diff", "commit",
		    bline->id_str, NULL);
		if (href_diff == NULL) {
			err = got_error_from_errno("khttp_urlpart");
			goto done;
		}
		kerr = khtml_attr(a->gw_trans->gw_html_req, KELEM_A,
		    KATTR_HREF, href_diff, KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_printf(a->gw_trans->gw_html_req, "%.8s",
		    bline->id_str);
		if (kerr != KCGI_OK)
			goto err;
		kerr = khtml_closeelem(a->gw_trans->gw_html_req, 2);
		if (kerr != KCGI_OK)
			goto err;

		kerr = khtml_attr(a->gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "blame_date", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto err;
		kerr = khtml_puts(a->gw_trans->gw_html_req, bline->datebuf);
		if (kerr != KCGI_OK)
			goto err;
		kerr = khtml_closeelem(a->gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto err;

		kerr = khtml_attr(a->gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "blame_author", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto err;
		kerr = khtml_puts(a->gw_trans->gw_html_req, committer);
		if (kerr != KCGI_OK)
			goto err;
		kerr = khtml_closeelem(a->gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto err;

		kerr = khtml_attr(a->gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "blame_code", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto err;
		kerr = khtml_puts(a->gw_trans->gw_html_req, line);
		if (kerr != KCGI_OK)
			goto err;
		kerr = khtml_closeelem(a->gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto err;

		kerr = khtml_closeelem(a->gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto err;

		a->lineno_cur++;
		bline = &a->lines[a->lineno_cur - 1];
err:
		free(href_diff);
	}
done:
	free(line);
	if (err == NULL && kerr != KCGI_OK)
		err = gw_kcgi_error(kerr);
	return err;
}

static const struct got_error *
gw_output_file_blame(struct gw_trans *gw_trans, struct gw_header *header)
{
	const struct got_error *error = NULL;
	struct got_object_id *obj_id = NULL;
	struct got_object_id *commit_id = NULL;
	struct got_commit_object *commit = NULL;
	struct got_blob_object *blob = NULL;
	char *path = NULL, *in_repo_path = NULL;
	struct gw_blame_cb_args bca;
	int i, obj_type, fd1 = -1, fd2 = -1, fd3 = -1;
	off_t filesize;
	FILE *f1 = NULL, *f2 = NULL;

	fd1 = got_opentempfd();
	if (fd1 == -1)
		return got_error_from_errno("got_opentempfd");
	fd2 = got_opentempfd();
	if (fd2 == -1) {
		error = got_error_from_errno("got_opentempfd");
		goto done;
	}
	fd3 = got_opentempfd();
	if (fd3 == -1) {
		error = got_error_from_errno("got_opentempfd");
		goto done;
	}

	memset(&bca, 0, sizeof(bca));

	if (asprintf(&path, "%s%s%s",
	    gw_trans->repo_folder ? gw_trans->repo_folder : "",
	    gw_trans->repo_folder ? "/" : "",
	    gw_trans->repo_file) == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}

	error = got_repo_map_path(&in_repo_path, gw_trans->repo, path);
	if (error)
		goto done;

	error = got_repo_match_object_id(&commit_id, NULL, gw_trans->commit_id,
	    GOT_OBJ_TYPE_COMMIT, &header->refs, gw_trans->repo);
	if (error)
		goto done;

	error = got_object_open_as_commit(&commit, gw_trans->repo, commit_id);
	if (error)
		goto done;

	error = got_object_id_by_path(&obj_id, gw_trans->repo, commit,
	    in_repo_path);
	if (error)
		goto done;

	if (obj_id == NULL) {
		error = got_error(GOT_ERR_NO_OBJ);
		goto done;
	}

	error = got_object_get_type(&obj_type, gw_trans->repo, obj_id);
	if (error)
		goto done;

	if (obj_type != GOT_OBJ_TYPE_BLOB) {
		error = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	error = got_object_open_as_blob(&blob, gw_trans->repo, obj_id, 8192,
	    fd1);
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
	bca.repo = gw_trans->repo;
	bca.gw_trans = gw_trans;

	fd1 = got_opentempfd();
	if (fd1 == -1) {
		error = got_error_from_errno("got_opentempfd");
		goto done;
	}

	f1 = got_opentemp();
	if (f1 == NULL) {
		error = got_error_from_errno("got_opentempfd");
		goto done;
	}
	f2 = got_opentemp();
	if (f2 == NULL) {
		error = got_error_from_errno("got_opentempfd");
		goto done;
	}

	error = got_blame(in_repo_path, commit_id, gw_trans->repo,
	    GOT_DIFF_ALGORITHM_PATIENCE, gw_blame_cb, &bca, NULL, NULL,
	    fd2, fd3, f1, f2);
done:
	free(in_repo_path);
	free(commit_id);
	free(obj_id);
	free(path);

	if (fd1 != -1 && close(fd1) == -1 && error == NULL)
		error = got_error_from_errno("close");
	if (fd2 != -1 && close(fd2) == -1 && error == NULL)
		error = got_error_from_errno("close");
	if (fd3 != -1 && close(fd3) == -1 && error == NULL)
		error = got_error_from_errno("close");
	if (f1 && fclose(f1) == EOF && error == NULL)
		error = got_error_from_errno("fclose");
	if (f2 && fclose(f2) == EOF && error == NULL)
		error = got_error_from_errno("fclose");

	if (blob) {
		free(bca.line_offsets);
		for (i = 0; i < bca.nlines; i++) {
			struct blame_line *bline = &bca.lines[i];
			free(bline->id_str);
			free(bline->committer);
		}
		free(bca.lines);
		if (bca.f && fclose(bca.f) == EOF && error == NULL)
			error = got_error_from_errno("fclose");
	}
	if (blob)
		got_object_blob_close(blob);
	if (commit)
		got_object_commit_close(commit);
	return error;
}

static const struct got_error *
gw_output_blob_buf(struct gw_trans *gw_trans, struct gw_header *header)
{
	const struct got_error *error = NULL;
	struct got_object_id *obj_id = NULL;
	struct got_object_id *commit_id = NULL;
	struct got_commit_object *commit = NULL;
	struct got_blob_object *blob = NULL;
	char *path = NULL, *in_repo_path = NULL;
	int obj_type, set_mime = 0, fd = -1;
	size_t len, hdrlen;
	const uint8_t *buf;
	enum kcgi_err kerr = KCGI_OK;

	fd = got_opentempfd();
	if (fd == -1)
		return got_error_from_errno("got_opentempfd");

	if (asprintf(&path, "%s%s%s",
	    gw_trans->repo_folder ? gw_trans->repo_folder : "",
	    gw_trans->repo_folder ? "/" : "",
	    gw_trans->repo_file) == -1) {
		error = got_error_from_errno("asprintf");
		goto done;
	}

	error = got_repo_map_path(&in_repo_path, gw_trans->repo, path);
	if (error)
		goto done;

	error = got_repo_match_object_id(&commit_id, NULL, gw_trans->commit_id,
	    GOT_OBJ_TYPE_COMMIT, &header->refs, gw_trans->repo);
	if (error)
		goto done;

	error = got_object_open_as_commit(&commit, gw_trans->repo, commit_id);
	if (error)
		goto done;

	error = got_object_id_by_path(&obj_id, gw_trans->repo, commit,
	    in_repo_path);
	if (error)
		goto done;

	if (obj_id == NULL) {
		error = got_error(GOT_ERR_NO_OBJ);
		goto done;
	}

	error = got_object_get_type(&obj_type, gw_trans->repo, obj_id);
	if (error)
		goto done;

	if (obj_type != GOT_OBJ_TYPE_BLOB) {
		error = got_error(GOT_ERR_OBJ_TYPE);
		goto done;
	}

	error = got_object_open_as_blob(&blob, gw_trans->repo, obj_id, 8192,
	    fd);
	if (error)
		goto done;

	hdrlen = got_object_blob_get_hdrlen(blob);
	do {
		error = got_object_blob_read_block(&len, blob);
		if (error)
			goto done;
		buf = got_object_blob_get_read_buf(blob);

		/*
		 * Skip blob object header first time around,
		 * which also contains a zero byte.
		 */
		buf += hdrlen;
		if (set_mime == 0) {
			if (isbinary(buf, len - hdrlen))
				gw_trans->mime = KMIME_APP_OCTET_STREAM;
			else
				gw_trans->mime = KMIME_TEXT_PLAIN;
			set_mime = 1;
			error = gw_display_index(gw_trans);
			if (error)
				goto done;
		}
		kerr = khttp_write(gw_trans->gw_req, buf, len - hdrlen);
		if (kerr != KCGI_OK)
			goto done;
		hdrlen = 0;
	} while (len != 0);
done:
	free(in_repo_path);
	free(commit_id);
	free(obj_id);
	free(path);
	if (fd != -1 && close(fd) == -1 && error == NULL)
		error = got_error_from_errno("close");
	if (blob)
		got_object_blob_close(blob);
	if (commit)
		got_object_commit_close(commit);
	if (error == NULL && kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
	return error;
}

static const struct got_error *
gw_output_repo_tree(struct gw_trans *gw_trans, struct gw_header *header)
{
	const struct got_error *error = NULL;
	struct got_object_id *tree_id = NULL, *commit_id = NULL;
	struct got_tree_object *tree = NULL;
	struct got_commit_object *commit = NULL;
	char *path = NULL, *in_repo_path = NULL;
	char *id_str = NULL;
	char *build_folder = NULL;
	char *href_blob = NULL, *href_blame = NULL;
	const char *class = NULL;
	int nentries, i, class_flip = 0;
	enum kcgi_err kerr = KCGI_OK;

	if (gw_trans->repo_folder != NULL) {
		path = strdup(gw_trans->repo_folder);
		if (path == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
	} else {
		error = got_repo_map_path(&in_repo_path, gw_trans->repo,
		    gw_trans->repo_path);
		if (error)
			goto done;
		free(path);
		path = in_repo_path;
	}

	if (gw_trans->commit_id == NULL) {
		struct got_reference *head_ref;
		error = got_ref_open(&head_ref, gw_trans->repo,
		    gw_trans->headref, 0);
		if (error)
			goto done;
		error = got_ref_resolve(&commit_id, gw_trans->repo, head_ref);
		if (error)
			goto done;
		got_ref_close(head_ref);
		/*
		 * gw_trans->commit_id was not parsed from the querystring
		 * we hit this code path from gw_index, where we don't know the
		 * commit values for the tree link yet, so set
		 * gw_trans->commit_id here to continue further into the tree
		 */
		error = got_object_id_str(&gw_trans->commit_id, commit_id);
		if (error)
			goto done;

	} else {
		error = got_repo_match_object_id(&commit_id, NULL,
		    gw_trans->commit_id, GOT_OBJ_TYPE_COMMIT, &header->refs,
		    gw_trans->repo);
		if (error)
			goto done;
	}

	error = got_object_open_as_commit(&commit, gw_trans->repo, commit_id);
	if (error)
		goto done;

	error = got_object_id_by_path(&tree_id, gw_trans->repo, commit,
	    path);
	if (error)
		goto done;

	error = got_object_open_as_tree(&tree, gw_trans->repo, tree_id);
	if (error)
		goto done;

	nentries = got_object_tree_get_nentries(tree);
	for (i = 0; i < nentries; i++) {
		struct got_tree_entry *te;
		const char *modestr = "";
		mode_t mode;

		te = got_object_tree_get_entry(tree, i);

		error = got_object_id_str(&id_str, got_tree_entry_get_id(te));
		if (error)
			goto done;

		mode = got_tree_entry_get_mode(te);
		if (got_object_tree_entry_is_submodule(te))
			modestr = "$";
		else if (S_ISLNK(mode))
			modestr = "@";
		else if (S_ISDIR(mode))
			modestr = "/";
		else if (mode & S_IXUSR)
			modestr = "*";

		if (class_flip == 0) {
			class = "back_lightgray";
			class_flip = 1;
		} else {
			class = "back_white";
			class_flip = 0;
		}

		if (S_ISDIR(mode)) {
			if (asprintf(&build_folder, "%s/%s",
			    gw_trans->repo_folder ? gw_trans->repo_folder : "",
			    got_tree_entry_get_name(te)) == -1) {
				error = got_error_from_errno("asprintf");
				goto done;
			}

			href_blob = khttp_urlpart(NULL, NULL, "gotweb", "path",
			    gw_trans->repo_name, "action",
			    gw_get_action_name(gw_trans), "commit",
			    gw_trans->commit_id, "folder", build_folder, NULL);
			if (href_blob == NULL) {
				error = got_error_from_errno("khttp_urlpart");
				goto done;
			}
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "tree_wrapper", KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "tree_line", KATTR_CLASS, class,
			    KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A,
			    KATTR_HREF, href_blob, KATTR_CLASS,
			    "diff_directory", KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_printf(gw_trans->gw_html_req, "%s%s",
			    got_tree_entry_get_name(te), modestr);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_closeelem(gw_trans->gw_html_req, 2);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "tree_line_blank", KATTR_CLASS, class,
			    KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_entity(gw_trans->gw_html_req,
			    KENTITY_nbsp);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_closeelem(gw_trans->gw_html_req, 2);
			if (kerr != KCGI_OK)
				goto done;
		} else {
			href_blob = khttp_urlpart(NULL, NULL, "gotweb", "path",
			    gw_trans->repo_name, "action", "blob", "commit",
			    gw_trans->commit_id, "file",
			    got_tree_entry_get_name(te), "folder",
			    gw_trans->repo_folder ? gw_trans->repo_folder : "",
			    NULL);
			if (href_blob == NULL) {
				error = got_error_from_errno("khttp_urlpart");
				goto done;
			}
			href_blame = khttp_urlpart(NULL, NULL, "gotweb", "path",
			    gw_trans->repo_name, "action", "blame", "commit",
			    gw_trans->commit_id, "file",
			    got_tree_entry_get_name(te), "folder",
			    gw_trans->repo_folder ? gw_trans->repo_folder : "",
			    NULL);
			if (href_blame == NULL) {
				error = got_error_from_errno("khttp_urlpart");
				goto done;
			}
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "tree_wrapper", KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "tree_line", KATTR_CLASS, class,
			    KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A,
			    KATTR_HREF, href_blob, KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_printf(gw_trans->gw_html_req, "%s%s",
			    got_tree_entry_get_name(te), modestr);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_closeelem(gw_trans->gw_html_req, 2);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
			    KATTR_ID, "tree_line_navs", KATTR_CLASS, class,
			    KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;

			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A,
			    KATTR_HREF, href_blob, KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_puts(gw_trans->gw_html_req, "blob");
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
			if (kerr != KCGI_OK)
				goto done;

			kerr = khtml_puts(gw_trans->gw_html_req, " | ");
			if (kerr != KCGI_OK)
				goto done;

			kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A,
			    KATTR_HREF, href_blame, KATTR__MAX);
			if (kerr != KCGI_OK)
				goto done;
			kerr = khtml_puts(gw_trans->gw_html_req, "blame");
			if (kerr != KCGI_OK)
				goto done;

			kerr = khtml_closeelem(gw_trans->gw_html_req, 3);
			if (kerr != KCGI_OK)
				goto done;
		}
		free(id_str);
		id_str = NULL;
		free(href_blob);
		href_blob = NULL;
		free(build_folder);
		build_folder = NULL;
	}
done:
	if (tree)
		got_object_tree_close(tree);
	if (commit)
		got_object_commit_close(commit);
	free(id_str);
	free(href_blob);
	free(href_blame);
	free(in_repo_path);
	free(tree_id);
	free(build_folder);
	if (error == NULL && kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
	return error;
}

static const struct got_error *
gw_output_repo_heads(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;
	char *age = NULL, *href_summary = NULL, *href_briefs = NULL;
	char *href_commits = NULL;
	enum kcgi_err kerr = KCGI_OK;

	TAILQ_INIT(&refs);

	error = got_ref_list(&refs, gw_trans->repo, "refs/heads",
	    got_ref_cmp_by_name, NULL);
	if (error)
		goto done;

	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
	    KATTR_ID, "summary_heads_title_wrapper", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
	    KATTR_ID, "summary_heads_title", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_puts(gw_trans->gw_html_req, "Heads");
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_closeelem(gw_trans->gw_html_req, 2);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
	    KATTR_ID, "summary_heads_content", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;

	TAILQ_FOREACH(re, &refs, entry) {
		const char *refname;

		if (got_ref_is_symbolic(re->ref))
			continue;

		refname = got_ref_get_name(re->ref);
		if (strncmp(refname, "refs/heads/", 11) != 0)
			continue;

		error = gw_get_repo_age(&age, gw_trans, gw_trans->gw_dir->path,
		    refname, TM_DIFF);
		if (error)
			goto done;

		if (strncmp(refname, "refs/heads/", 11) == 0)
			refname += 11;

		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "heads_wrapper", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "heads_age", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req, age ? age : "");
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "heads_space", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_entity(gw_trans->gw_html_req, KENTITY_nbsp);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV,
		    KATTR_ID, "head", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;

		href_summary = khttp_urlpart(NULL, NULL, "gotweb", "path",
		    gw_trans->repo_name, "action", "summary", "headref",
		    refname, NULL);
		if (href_summary == NULL) {
			error = got_error_from_errno("khttp_urlpart");
			goto done;
		}
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A, KATTR_HREF,
		    href_summary, KATTR__MAX);
		kerr = khtml_puts(gw_trans->gw_html_req, refname);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 3);
		if (kerr != KCGI_OK)
			goto done;

		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "navs_wrapper", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "navs", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;

		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A, KATTR_HREF,
		    href_summary, KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req, "summary");
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;

		kerr = khtml_puts(gw_trans->gw_html_req, " | ");
		if (kerr != KCGI_OK)
			goto done;

		href_briefs = khttp_urlpart(NULL, NULL, "gotweb", "path",
		    gw_trans->repo_name, "action", "briefs", "headref",
		    refname, NULL);
		if (href_briefs == NULL) {
			error = got_error_from_errno("khttp_urlpart");
			goto done;
		}
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A, KATTR_HREF,
		    href_briefs, KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req, "commit briefs");
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;

		kerr = khtml_puts(gw_trans->gw_html_req, " | ");
		if (kerr != KCGI_OK)
			goto done;

		href_commits = khttp_urlpart(NULL, NULL, "gotweb", "path",
		    gw_trans->repo_name, "action", "commits", "headref",
		    refname, NULL);
		if (href_commits == NULL) {
			error = got_error_from_errno("khttp_urlpart");
			goto done;
		}
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A, KATTR_HREF,
		    href_commits, KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req, "commits");
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 3);
		if (kerr != KCGI_OK)
			goto done;

		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
		    "dotted_line", KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 2);
		if (kerr != KCGI_OK)
			goto done;
		free(href_summary);
		href_summary = NULL;
		free(href_briefs);
		href_briefs = NULL;
		free(href_commits);
		href_commits = NULL;
	}
done:
	got_ref_list_free(&refs);
	free(href_summary);
	free(href_briefs);
	free(href_commits);
	return error;
}

static const struct got_error *
gw_output_site_link(struct gw_trans *gw_trans)
{
	const struct got_error *error = NULL;
	char *href_summary = NULL;
	enum kcgi_err kerr = KCGI_OK;

	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
	    "site_link", KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A, KATTR_HREF, GOTWEB,
	    KATTR__MAX);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_puts(gw_trans->gw_html_req,
	    gw_trans->gw_conf->got_site_link);
	if (kerr != KCGI_OK)
		goto done;
	kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
	if (kerr != KCGI_OK)
		goto done;

	if (gw_trans->repo_name != NULL) {
		kerr = khtml_puts(gw_trans->gw_html_req, " / ");
		if (kerr != KCGI_OK)
			goto done;

		href_summary = khttp_urlpart(NULL, NULL, "gotweb", "path",
		    gw_trans->repo_name, "action", "summary", NULL);
		if (href_summary == NULL) {
			error = got_error_from_errno("khttp_urlpart");
			goto done;
		}
		kerr = khtml_attr(gw_trans->gw_html_req, KELEM_A, KATTR_HREF,
		    href_summary, KATTR__MAX);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_puts(gw_trans->gw_html_req, gw_trans->repo_name);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
		if (kerr != KCGI_OK)
			goto done;
		kerr = khtml_printf(gw_trans->gw_html_req, " / %s",
		    gw_get_action_name(gw_trans));
		if (kerr != KCGI_OK)
			goto done;
	}

	kerr = khtml_closeelem(gw_trans->gw_html_req, 1);
	if (kerr != KCGI_OK)
		goto done;
done:
	free(href_summary);
	if (error == NULL && kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
	return error;
}

static const struct got_error *
gw_colordiff_line(struct gw_trans *gw_trans, char *buf)
{
	const struct got_error *error = NULL;
	const char *color = NULL;
	enum kcgi_err kerr = KCGI_OK;

	if (strncmp(buf, "-", 1) == 0)
		color = "diff_minus";
	else if (strncmp(buf, "+", 1) == 0)
		color = "diff_plus";
	else if (strncmp(buf, "@@", 2) == 0)
		color = "diff_chunk_header";
	else if (strncmp(buf, "@@", 2) == 0)
		color = "diff_chunk_header";
	else if (strncmp(buf, "commit +", 8) == 0)
		color = "diff_meta";
	else if (strncmp(buf, "commit -", 8) == 0)
		color = "diff_meta";
	else if (strncmp(buf, "blob +", 6) == 0)
		color = "diff_meta";
	else if (strncmp(buf, "blob -", 6) == 0)
		color = "diff_meta";
	else if (strncmp(buf, "file +", 6) == 0)
		color = "diff_meta";
	else if (strncmp(buf, "file -", 6) == 0)
		color = "diff_meta";
	else if (strncmp(buf, "from:", 5) == 0)
		color = "diff_author";
	else if (strncmp(buf, "via:", 4) == 0)
		color = "diff_author";
	else if (strncmp(buf, "date:", 5) == 0)
		color = "diff_date";
	kerr = khtml_attr(gw_trans->gw_html_req, KELEM_DIV, KATTR_ID,
	    "diff_line", KATTR_CLASS, color ? color : "", KATTR__MAX);
	if (error == NULL && kerr != KCGI_OK)
		error = gw_kcgi_error(kerr);
	return error;
}

int
main(int argc, char *argv[])
{
	const struct got_error *error = NULL, *error2 = NULL;
	struct gw_trans *gw_trans;
	struct gw_dir *dir = NULL, *tdir;
	const char *page = "index";
	enum kcgi_err kerr = KCGI_OK;

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

	TAILQ_INIT(&gw_trans->gw_dirs);
	TAILQ_INIT(&gw_trans->gw_headers);

	gw_trans->action = -1;
	gw_trans->page = 0;
	gw_trans->repos_total = 0;
	gw_trans->repo_path = NULL;
	gw_trans->commit_id = NULL;
	gw_trans->next_id = NULL;
	gw_trans->prev_id = NULL;
	gw_trans->headref = GOT_REF_HEAD;
	gw_trans->mime = KMIME_TEXT_HTML;
	gw_trans->gw_tmpl->key = gw_templs;
	gw_trans->gw_tmpl->keysz = TEMPL__MAX;
	gw_trans->gw_tmpl->arg = gw_trans;
	gw_trans->gw_tmpl->cb = gw_template;

	error = got_repo_pack_fds_open(&gw_trans->pack_fds);
	if (error != NULL)
		goto done;

	error = parse_gotweb_config(&gw_trans->gw_conf, GOTWEB_CONF);
	if (error)
		goto done;

	error = gw_parse_querystring(gw_trans);
	if (error)
		goto done;

	if (gw_trans->repo) {
		const struct got_error *close_err;
		close_err = got_repo_close(gw_trans->repo);
		if (error == NULL)
			error = close_err;
	}
	if (gw_trans->action == GW_BLOB)
		error = gw_blob(gw_trans);
	else
		error = gw_display_index(gw_trans);
done:
	if (error) {
		gw_trans->error = error;
		gw_trans->action = GW_ERR;
		error2 = gw_display_open(gw_trans, KHTTP_200, gw_trans->mime);
		if (error2)
			goto cleanup; /* we can't display an error page */
		kerr = khtml_open(gw_trans->gw_html_req, gw_trans->gw_req, 0);
		if (kerr != KCGI_OK)
			goto cleanup; /* we can't display an error page */
		kerr = khttp_template(gw_trans->gw_req, gw_trans->gw_tmpl,
			gw_query_funcs[gw_trans->action].template);
		if (kerr != KCGI_OK) {
			khtml_close(gw_trans->gw_html_req);
			goto cleanup; /* we can't display an error page */
		}
	}

cleanup:
	if (gw_trans->pack_fds) {
		const struct got_error *pack_err =
		    got_repo_pack_fds_close(gw_trans->pack_fds);
		if (error == NULL)
			error = pack_err;
		gw_trans->pack_fds = NULL;
	}
	free(gw_trans->gw_conf->got_repos_path);
	free(gw_trans->gw_conf->got_www_path);
	free(gw_trans->gw_conf->got_site_name);
	free(gw_trans->gw_conf->got_site_owner);
	free(gw_trans->gw_conf->got_site_link);
	free(gw_trans->gw_conf->got_logo);
	free(gw_trans->gw_conf->got_logo_url);
	free(gw_trans->gw_conf);
	free(gw_trans->commit_id);
	free(gw_trans->next_id);
	free(gw_trans->prev_id);
	free(gw_trans->repo_path);
	TAILQ_FOREACH_SAFE(dir, &gw_trans->gw_dirs, entry, tdir) {
		free(dir->name);
		free(dir->description);
		free(dir->age);
		free(dir->url);
		free(dir->path);
		free(dir);
	}

	khttp_free(gw_trans->gw_req);
	return 0;
}
