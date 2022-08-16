/*
 * Copyright (c) 2016, 2019, 2020-2022 Tracey Emery <tracey@traceyemery.net>
 * Copyright (c) 2015 Mike Larkin <mlarkin@openbsd.org>
 * Copyright (c) 2013 David Gwynne <dlg@openbsd.org>
 * Copyright (c) 2013 Florian Obser <florian@openbsd.org>
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

#include <net/if.h>
#include <netinet/in.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <dirent.h>
#include <errno.h>
#include <event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "got_error.h"
#include "got_object.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_path.h"
#include "got_cancel.h"
#include "got_worktree.h"
#include "got_diff.h"
#include "got_commit_graph.h"
#include "got_blame.h"
#include "got_privsep.h"

#include "proc.h"
#include "gotwebd.h"

#include "got_compat.h"

enum gotweb_ref_tm {
	TM_DIFF,
	TM_LONG,
};

static const struct querystring_keys querystring_keys[] = {
	{ "action",		ACTION },
	{ "commit",		COMMIT },
	{ "file",		RFILE },
	{ "folder",		FOLDER },
	{ "headref",		HEADREF },
	{ "index_page",		INDEX_PAGE },
	{ "path",		PATH },
	{ "page",		PAGE },
};

static const struct action_keys action_keys[] = {
	{ "blame",	BLAME },
	{ "blob",	BLOB },
	{ "briefs",	BRIEFS },
	{ "commits",	COMMITS },
	{ "diff",	DIFF },
	{ "error",	ERR },
	{ "index",	INDEX },
	{ "summary",	SUMMARY },
	{ "tag",	TAG },
	{ "tags",	TAGS },
	{ "tree",	TREE },
};

static const struct got_error *gotweb_init_querystring(struct querystring **);
static const struct got_error *gotweb_parse_querystring(struct querystring **,
    char *);
static const struct got_error *gotweb_assign_querystring(struct querystring **,
    char *, char *);
static const struct got_error *gotweb_render_header(struct request *);
static const struct got_error *gotweb_render_footer(struct request *);
static const struct got_error *gotweb_render_index(struct request *);
static const struct got_error *gotweb_init_repo_dir(struct repo_dir **,
    const char *);
static const struct got_error *gotweb_load_got_path(struct request *c,
    struct repo_dir *);
static const struct got_error *gotweb_get_repo_description(char **,
    struct server *, char *);
static const struct got_error *gotweb_get_clone_url(char **, struct server *,
    char *);
static const struct got_error *gotweb_render_navs(struct request *);
static const struct got_error *gotweb_render_blame(struct request *);
static const struct got_error *gotweb_render_briefs(struct request *);
static const struct got_error *gotweb_render_commits(struct request *);
static const struct got_error *gotweb_render_diff(struct request *);
static const struct got_error *gotweb_render_summary(struct request *);
static const struct got_error *gotweb_render_tag(struct request *);
static const struct got_error *gotweb_render_tags(struct request *);
static const struct got_error *gotweb_render_tree(struct request *);
static const struct got_error *gotweb_render_branches(struct request *);

static void gotweb_free_querystring(struct querystring *);
static void gotweb_free_repo_dir(struct repo_dir *);

struct server *gotweb_get_server(uint8_t *, uint8_t *, uint8_t *);

void
gotweb_process_request(struct request *c)
{
	const struct got_error *error = NULL, *error2 = NULL;
	struct server *srv = NULL;
	struct querystring *qs = NULL;
	struct repo_dir *repo_dir = NULL;
	uint8_t err[] = "gotwebd experienced an error: ";
	int html = 0;

	/* init the transport */
	error = gotweb_init_transport(&c->t);
	if (error) {
		log_warnx("%s: %s", __func__, error->msg);
		goto err;
	}
	/* don't process any further if client disconnected */
	if (c->sock->client_status == CLIENT_DISCONNECT)
		return;
	/* get the gotwebd server */
	srv = gotweb_get_server(c->server_name, c->document_root, c->http_host);
	if (srv == NULL) {
		log_warnx("%s: error server is NULL", __func__);
		goto err;
	}
	c->srv = srv;
	/* parse our querystring */
	error = gotweb_init_querystring(&qs);
	if (error) {
		log_warnx("%s: %s", __func__, error->msg);
		goto err;
	}
	c->t->qs = qs;
	error = gotweb_parse_querystring(&qs, c->querystring);
	if (error) {
		log_warnx("%s: %s", __func__, error->msg);
		goto err;
	}

	/*
	 * certain actions require a commit id in the querystring. this stops
	 * bad actors from exploiting this by manually manipulating the
	 * querystring.
	 */

	if (qs->commit == NULL && (qs->action == BLAME || qs->action == BLOB ||
	    qs->action == DIFF)) {
		error2 = got_error(GOT_ERR_QUERYSTRING);
		goto render;
	}

	if (qs->action != INDEX) {
		error = gotweb_init_repo_dir(&repo_dir, qs->path);
		if (error)
			goto done;
		error = gotweb_load_got_path(c, repo_dir);
		c->t->repo_dir = repo_dir;
		if (error && error->code != GOT_ERR_LONELY_PACKIDX)
			goto err;
	}

	/* render top of page */
	if (qs != NULL && qs->action == BLOB) {
		error = got_get_repo_commits(c, 1);
		if (error)
			goto done;
		error = got_output_file_blob(c);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		goto done;
	} else {
render:
		error = gotweb_render_content_type(c, "text/html");
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		html = 1;
	}

	error = gotweb_render_header(c);
	if (error) {
		log_warnx("%s: %s", __func__, error->msg);
		goto err;
	}

	if (error2) {
		error = error2;
		goto err;
	}

	switch(qs->action) {
	case BLAME:
		error = gotweb_render_blame(c);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		break;
	case BRIEFS:
		error = gotweb_render_briefs(c);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		break;
	case COMMITS:
		error = gotweb_render_commits(c);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		break;
	case DIFF:
		error = gotweb_render_diff(c);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		break;
	case INDEX:
		error = gotweb_render_index(c);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		break;
	case SUMMARY:
		error = gotweb_render_summary(c);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		break;
	case TAG:
		error = gotweb_render_tag(c);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		break;
	case TAGS:
		error = gotweb_render_tags(c);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		break;
	case TREE:
		error = gotweb_render_tree(c);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		break;
	case ERR:
	default:
		if (fcgi_gen_response(c, "<div id='err_content'>") == -1)
			goto err;
		if (fcgi_gen_response(c, "Error: Bad Querystring\n") == -1)
			goto err;
		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto err;
		break;
	}

	goto done;
err:
	if (html && fcgi_gen_response(c, "<div id='err_content'>") == -1)
		return;
	if (fcgi_gen_response(c, err) == -1)
		return;
	if (error) {
		if (fcgi_gen_response(c, (uint8_t *)error->msg) == -1)
			return;
	} else {
		if (fcgi_gen_response(c, "see daemon logs for details") == -1)
			return;
	}
	if (html && fcgi_gen_response(c, "</div>\n") == -1)
		return;
done:
	if (c->t->repo != NULL && qs->action != INDEX)
		got_repo_close(c->t->repo);
	if (html && srv != NULL)
		gotweb_render_footer(c);
}

struct server *
gotweb_get_server(uint8_t *server_name, uint8_t *document_root,
    uint8_t *subdomain)
{
	struct server *srv = NULL;

	/* check against document_root first */
	if (strlen(server_name) > 0)
		TAILQ_FOREACH(srv, &gotwebd_env->servers, entry)
			if (strcmp(srv->name, server_name) == 0)
				goto done;

	/* check against document_root second */
	if (strlen(document_root) > 0)
		TAILQ_FOREACH(srv, &gotwebd_env->servers, entry)
			if (strcmp(srv->name, document_root) == 0)
				goto done;

	/* check against subdomain third */
	if (strlen(subdomain) > 0)
		TAILQ_FOREACH(srv, &gotwebd_env->servers, entry)
			if (strcmp(srv->name, subdomain) == 0)
				goto done;

	/* if those fail, send first server */
	TAILQ_FOREACH(srv, &gotwebd_env->servers, entry)
		if (srv != NULL)
			break;
done:
	return srv;
};

const struct got_error *
gotweb_init_transport(struct transport **t)
{
	const struct got_error *error = NULL;

	*t = calloc(1, sizeof(**t));
	if (*t == NULL)
		return got_error_from_errno2("%s: calloc", __func__);

	TAILQ_INIT(&(*t)->repo_commits);
	TAILQ_INIT(&(*t)->repo_tags);

	(*t)->repo = NULL;
	(*t)->repo_dir = NULL;
	(*t)->qs = NULL;
	(*t)->next_id = NULL;
	(*t)->prev_id = NULL;
	(*t)->next_disp = 0;
	(*t)->prev_disp = 0;

	return error;
}

static const struct got_error *
gotweb_init_querystring(struct querystring **qs)
{
	const struct got_error *error = NULL;

	*qs = calloc(1, sizeof(**qs));
	if (*qs == NULL)
		return got_error_from_errno2("%s: calloc", __func__);

	(*qs)->action = INDEX;
	(*qs)->commit = NULL;
	(*qs)->file = NULL;
	(*qs)->folder = NULL;
	(*qs)->headref = strdup("HEAD");
	if ((*qs)->headref == NULL) {
		return got_error_from_errno2("%s: strdup", __func__);
	}
	(*qs)->index_page = 0;
	(*qs)->index_page_str = NULL;
	(*qs)->path = NULL;

	return error;
}

static const struct got_error *
gotweb_parse_querystring(struct querystring **qs, char *qst)
{
	const struct got_error *error = NULL;
	char *tok1 = NULL, *tok1_pair = NULL, *tok1_end = NULL;
	char *tok2 = NULL, *tok2_pair = NULL, *tok2_end = NULL;

	if (qst == NULL)
		return error;

	tok1 = strdup(qst);
	if (tok1 == NULL)
		return got_error_from_errno2("%s: strdup", __func__);

	tok1_pair = tok1;
	tok1_end = tok1;

	while (tok1_pair != NULL) {
		strsep(&tok1_end, "&");

		tok2 = strdup(tok1_pair);
		if (tok2 == NULL) {
			free(tok1);
			return got_error_from_errno2("%s: strdup", __func__);
		}

		tok2_pair = tok2;
		tok2_end = tok2;

		while (tok2_pair != NULL) {
			strsep(&tok2_end, "=");
			if (tok2_end) {
				error = gotweb_assign_querystring(qs, tok2_pair,
				    tok2_end);
				if (error)
					goto err;
			}
			tok2_pair = tok2_end;
		}
		free(tok2);
		tok1_pair = tok1_end;
	}
	free(tok1);
	return error;
err:
	free(tok2);
	free(tok1);
	return error;
}

static const struct got_error *
gotweb_assign_querystring(struct querystring **qs, char *key, char *value)
{
	const struct got_error *error = NULL;
	const char *errstr;
	int a_cnt, el_cnt;

	for (el_cnt = 0; el_cnt < QSELEM__MAX; el_cnt++) {
		if (strcmp(key, querystring_keys[el_cnt].name) != 0)
			continue;

		switch (querystring_keys[el_cnt].element) {
		case ACTION:
			for (a_cnt = 0; a_cnt < ACTIONS__MAX; a_cnt++) {
				if (strcmp(value, action_keys[a_cnt].name) != 0)
					continue;
				else if (strcmp(value,
				    action_keys[a_cnt].name) == 0){
					(*qs)->action =
					    action_keys[a_cnt].action;
					goto qa_found;
				}
			}
			(*qs)->action = ERR;
qa_found:
			break;
		case COMMIT:
			(*qs)->commit = strdup(value);
			if ((*qs)->commit == NULL) {
				error = got_error_from_errno2("%s: strdup",
				    __func__);
				goto done;
			}
			break;
		case RFILE:
			(*qs)->file = strdup(value);
			if ((*qs)->file == NULL) {
				error = got_error_from_errno2("%s: strdup",
				    __func__);
				goto done;
			}
			break;
		case FOLDER:
			(*qs)->folder = strdup(value);
			if ((*qs)->folder == NULL) {
				error = got_error_from_errno2("%s: strdup",
				    __func__);
				goto done;
			}
			break;
		case HEADREF:
			(*qs)->headref = strdup(value);
			if ((*qs)->headref == NULL) {
				error = got_error_from_errno2("%s: strdup",
				    __func__);
				goto done;
			}
			break;
		case INDEX_PAGE:
			if (strlen(value) == 0)
				break;
			(*qs)->index_page_str = strdup(value);
			if ((*qs)->index_page_str == NULL) {
				error = got_error_from_errno2("%s: strdup",
				    __func__);
				goto done;
			}
			(*qs)->index_page = strtonum(value, INT64_MIN,
			    INT64_MAX, &errstr);
			if (errstr) {
				error = got_error_from_errno3("%s: strtonum %s",
				    __func__, errstr);
				goto done;
			}
			if ((*qs)->index_page < 0) {
				(*qs)->index_page = 0;
				sprintf((*qs)->index_page_str, "%d", 0);
			}
			break;
		case PATH:
			(*qs)->path = strdup(value);
			if ((*qs)->path == NULL) {
				error = got_error_from_errno2("%s: strdup",
				    __func__);
				goto done;
			}
			break;
		case PAGE:
			if (strlen(value) == 0)
				break;
			(*qs)->page_str = strdup(value);
			if ((*qs)->page_str == NULL) {
				error = got_error_from_errno2("%s: strdup",
				    __func__);
				goto done;
			}
			(*qs)->page = strtonum(value, INT64_MIN,
			    INT64_MAX, &errstr);
			if (errstr) {
				error = got_error_from_errno3("%s: strtonum %s",
				    __func__, errstr);
				goto done;
			}
			if ((*qs)->page < 0) {
				(*qs)->page = 0;
				sprintf((*qs)->page_str, "%d", 0);
			}
			break;
		default:
			break;
		}
	}
done:
	return error;
}

void
gotweb_free_repo_tag(struct repo_tag *rt)
{
	if (rt != NULL) {
		free(rt->commit_msg);
		free(rt->commit_id);
		free(rt->tagger);
	}
	free(rt);
}

void
gotweb_free_repo_commit(struct repo_commit *rc)
{
	if (rc != NULL) {
		free(rc->path);
		free(rc->refs_str);
		free(rc->commit_id);
		free(rc->parent_id);
		free(rc->tree_id);
		free(rc->author);
		free(rc->committer);
		free(rc->commit_msg);
	}
	free(rc);
}

static void
gotweb_free_querystring(struct querystring *qs)
{
	if (qs != NULL) {
		free(qs->commit);
		free(qs->file);
		free(qs->folder);
		free(qs->headref);
		free(qs->index_page_str);
		free(qs->path);
		free(qs->page_str);
	}
	free(qs);
}

static void
gotweb_free_repo_dir(struct repo_dir *repo_dir)
{
	if (repo_dir != NULL) {
		free(repo_dir->name);
		free(repo_dir->owner);
		free(repo_dir->description);
		free(repo_dir->url);
		free(repo_dir->age);
		free(repo_dir->path);
	}
	free(repo_dir);
}

void
gotweb_free_transport(struct transport *t)
{
	struct repo_commit *rc = NULL, *trc = NULL;
	struct repo_tag *rt = NULL, *trt = NULL;

	TAILQ_FOREACH_SAFE(rc, &t->repo_commits, entry, trc) {
		TAILQ_REMOVE(&t->repo_commits, rc, entry);
		gotweb_free_repo_commit(rc);
	}
	TAILQ_FOREACH_SAFE(rt, &t->repo_tags, entry, trt) {
		TAILQ_REMOVE(&t->repo_tags, rt, entry);
		gotweb_free_repo_tag(rt);
	}
	gotweb_free_repo_dir(t->repo_dir);
	gotweb_free_querystring(t->qs);
	if (t != NULL) {
		free(t->next_id);
		free(t->prev_id);
	}
	free(t);
}

const struct got_error *
gotweb_render_content_type(struct request *c, const uint8_t *type)
{
	const struct got_error *error = NULL;
	char *h = NULL;

	if (asprintf(&h, "Content-type: %s\r\n\r\n", type) == -1) {
		error = got_error_from_errno2("%s: asprintf", __func__);
		goto done;
	}

	fcgi_gen_response(c, h);
done:
	free(h);

	return error;
}

const struct got_error *
gotweb_render_content_type_file(struct request *c, const uint8_t *type,
    char *file)
{
	const struct got_error *error = NULL;
	char *h = NULL;

	if (asprintf(&h, "Content-type: %s\r\n"
	    "Content-disposition: attachment; filename=%s\r\n\r\n",
	    type, file) == -1) {
		error = got_error_from_errno2("%s: asprintf", __func__);
		goto done;
	}

	fcgi_gen_response(c, h);
done:
	free(h);

	return error;
}

static const struct got_error *
gotweb_render_header(struct request *c)
{
	const struct got_error *error = NULL;
	struct server *srv = c->srv;
	struct querystring *qs = c->t->qs;
	char *title = NULL, *droot = NULL, *css = NULL, *gotlink = NULL;
	char *gotimg = NULL, *sitelink = NULL, *summlink = NULL;

	if (strlen(c->document_root) > 0) {
		if (asprintf(&droot, "/%s/", c->document_root) == -1) {
			error = got_error_from_errno2("%s: asprintf", __func__);
			goto done;
		}
	} else {
		if (asprintf(&droot, "/") == -1) {
			error = got_error_from_errno2("%s: asprintf", __func__);
			goto done;
		}
	}

	if (asprintf(&title, "<title>%s</title>\n", srv->site_name) == -1) {
		error = got_error_from_errno2("%s: asprintf", __func__);
		goto done;
	}
	if (asprintf(&css,
	    "<link rel='stylesheet' type='text/css' href='%s%s'/>\n",
	    droot, srv->custom_css) == -1) {
		error = got_error_from_errno2("%s: asprintf", __func__);
		goto done;
	}
	if (asprintf(&gotlink, "<a href='%s' target='_sotd'>",
	    srv->logo_url) == -1) {
		error = got_error_from_errno2("%s: asprintf", __func__);
		goto done;
	}
	if (asprintf(&gotimg, "<img src='%s%s' alt='logo' id='logo'/></a>",
	    droot, srv->logo) == -1) {
		error = got_error_from_errno2("%s: asprintf", __func__);
		goto done;
	}
	if (asprintf(&sitelink, "<a href='/%s?index_page=%d' "
	    "alt='sitelink'>%s</a>", c->document_root, qs->index_page,
	    srv->site_link) == -1) {
		error = got_error_from_errno2("%s: asprintf", __func__);
		goto done;
	}
	if (asprintf(&summlink, "<a href='/%s?index_page=%d&path=%s"
	    "&action=summary' alt='summlink'>%s</a>", c->document_root,
	    qs->index_page, qs->path, qs->path) == -1) {
		error = got_error_from_errno2("%s: asprintf", __func__);
		goto done;
	}

	if (fcgi_gen_response(c, "<!DOCTYPE html>\n<head>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, title) == -1)
		goto done;
	if (fcgi_gen_response(c, "<meta name='viewport' "
	    "content='initial-scale=.75, user-scalable=yes'/>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<meta charset='utf-8'/>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<meta name='msapplication-TileColor' "
	    "content='#da532c'/>\n") == -1)
		goto done;
	if (fcgi_gen_response(c,
	    "<meta name='theme-color' content='#ffffff'/>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<link rel='apple-touch-icon' sizes='180x180' "
	    "href='/apple-touch-icon.png'/>\n") == -1)
		goto done;
	if (fcgi_gen_response(c,
	    "<link rel='icon' type='image/png' sizes='32x32' "
	    "href='/favicon-32x32.png'/>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<link rel='icon' type='image/png' "
	    "sizes='16x16' href='/favicon-16x16.png'/>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<link rel='manifest' "
	    "href='/site.webmanifest'/>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<link rel='mask-icon' "
	    "href='/safari-pinned-tab.svg'/>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, css) == -1)
		goto done;
	if (fcgi_gen_response(c, "</head>\n<body>\n<div id='gw_body'>\n") == -1)
		goto done;
	if (fcgi_gen_response(c,
	    "<div id='header'>\n<div id='got_link'>") == -1)
		goto done;
	if (fcgi_gen_response(c, gotlink) == -1)
		goto done;
	if (fcgi_gen_response(c, gotimg) == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c,
	    "<div id='site_path'>\n<div id='site_link'>") == -1)
		goto done;
	if (fcgi_gen_response(c, sitelink) == -1)
		goto done;
	if (qs != NULL) {
		if (qs->path != NULL) {
			if (fcgi_gen_response(c, " / ") == -1)
				goto done;
			if (fcgi_gen_response(c, summlink) == -1)
				goto done;
		}
		if (qs->action != INDEX) {
			if (fcgi_gen_response(c, " / ") == -1)
				goto done;
			switch(qs->action) {
			case(BLAME):
				if (fcgi_gen_response(c, "blame") == -1)
					goto done;
				break;
			case(BRIEFS):
				if (fcgi_gen_response(c, "briefs") == -1)
					goto done;
				break;
			case(COMMITS):
				if (fcgi_gen_response(c, "commits") == -1)
					goto done;
				break;
			case(DIFF):
				if (fcgi_gen_response(c, "diff") == -1)
					goto done;
				break;
			case(SUMMARY):
				if (fcgi_gen_response(c, "summary") == -1)
					goto done;
				break;
			case(TAG):
				if (fcgi_gen_response(c, "tag") == -1)
					goto done;
				break;
			case(TAGS):
				if (fcgi_gen_response(c, "tags") == -1)
					goto done;
				break;
			case(TREE):
				if (fcgi_gen_response(c, "tree") == -1)
					goto done;
				break;
			default:
				break;
			}
		}

	}
	fcgi_gen_response(c, "</div>\n</div>\n<div id='content'>\n");
done:
	free(title);
	free(droot);
	free(css);
	free(gotlink);
	free(gotimg);
	free(sitelink);
	free(summlink);

	return error;
}

static const struct got_error *
gotweb_render_footer(struct request *c)
{
	const struct got_error *error = NULL;
	struct server *srv = c->srv;
	char *siteowner = NULL;

	if (fcgi_gen_response(c, "<div id='site_owner_wrapper'>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='site_owner'>") == -1)
		goto done;
	if (srv->show_site_owner) {
		error = gotweb_escape_html(&siteowner, srv->site_owner);
		if (error)
			goto done;
		if (fcgi_gen_response(c, siteowner) == -1)
			goto done;
	} else
		if (fcgi_gen_response(c, "&nbsp;") == -1)
			goto done;
	fcgi_gen_response(c, "</div>\n</div>\n</div>\n</body>\n</html>");
done:
	free(siteowner);

	return error;
}

static const struct got_error *
gotweb_render_navs(struct request *c)
{
	const struct got_error *error = NULL;
	struct transport *t = c->t;
	struct querystring *qs = t->qs;
	struct server *srv = c->srv;
	char *nhref = NULL, *phref = NULL;
	int disp = 0;

	if (fcgi_gen_response(c, "<div id='np_wrapper'>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='nav_prev'>") == -1)
		goto done;

	switch(qs->action) {
	case INDEX:
		if (qs->index_page > 0) {
			if (asprintf(&phref, "index_page=%d",
			    qs->index_page - 1) == -1) {
				error = got_error_from_errno2("%s: asprintf",
				    __func__);
				goto done;
			}
			disp = 1;
		}
		break;
	case BRIEFS:
		if (t->prev_id && qs->commit != NULL &&
		    strcmp(qs->commit, t->prev_id) != 0) {
			if (asprintf(&phref, "index_page=%d&path=%s&page=%d"
			    "&action=briefs&commit=%s&headref=%s",
			    qs->index_page, qs->path, qs->page - 1, t->prev_id,
			    qs->headref) == -1) {
				error = got_error_from_errno2("%s: asprintf",
				    __func__);
				goto done;
			}
			disp = 1;
		}
		break;
	case COMMITS:
		if (t->prev_id && qs->commit != NULL &&
		    strcmp(qs->commit, t->prev_id) != 0) {
			if (asprintf(&phref, "index_page=%d&path=%s&page=%d"
			    "&action=commits&commit=%s&headref=%s&folder=%s"
			    "&file=%s",
			    qs->index_page, qs->path, qs->page - 1, t->prev_id,
			    qs->headref, qs->folder ? qs->folder : "",
			    qs->file ? qs->file : "") == -1) {
				error = got_error_from_errno2("%s: asprintf",
				    __func__);
				goto done;
			}
			disp = 1;
		}
		break;
	case TAGS:
		if (t->prev_id && qs->commit != NULL &&
		    strcmp(qs->commit, t->prev_id) != 0) {
			if (asprintf(&phref, "index_page=%d&path=%s&page=%d"
			    "&action=tags&commit=%s&headref=%s",
			    qs->index_page, qs->path, qs->page - 1, t->prev_id,
			    qs->headref) == -1) {
				error = got_error_from_errno2("%s: asprintf",
				    __func__);
				goto done;
			}
			disp = 1;
		}
		break;
	default:
		disp = 0;
		break;
	}

	if (disp) {
		if (fcgi_gen_response(c, "<a href='?") == -1)
			goto  done;
		if (fcgi_gen_response(c, phref) == -1)
			goto done;
		if (fcgi_gen_response(c, "'>Previous</a>") == -1)
			goto done;
	}
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='nav_next'>") == -1)
		goto done;

	disp = 0;

	switch(qs->action) {
	case INDEX:
		if (t->next_disp == srv->max_repos_display &&
		    t->repos_total != (qs->index_page + 1) *
		    srv->max_repos_display) {
			if (asprintf(&nhref, "index_page=%d",
			    qs->index_page + 1) == -1) {
				error = got_error_from_errno2("%s: asprintf",
				    __func__);
				goto done;
			}
			disp = 1;
		}
		break;
	case BRIEFS:
		if (t->next_id) {
			if (asprintf(&nhref, "index_page=%d&path=%s&page=%d"
			    "&action=briefs&commit=%s&headref=%s",
			    qs->index_page, qs->path, qs->page + 1, t->next_id,
			    qs->headref) == -1) {
				error = got_error_from_errno2("%s: asprintf",
				    __func__);
				goto done;
			}
			disp = 1;
		}
		break;
	case COMMITS:
		if (t->next_id) {
			if (asprintf(&nhref, "index_page=%d&path=%s&page=%d"
			    "&action=commits&commit=%s&headref=%s&folder=%s"
			    "&file=%s",
			    qs->index_page, qs->path, qs->page + 1, t->next_id,
			    qs->headref, qs->folder ? qs->folder : "",
			    qs->file ? qs->file : "") == -1) {
				error = got_error_from_errno2("%s: asprintf",
				    __func__);
				goto done;
			}
			disp = 1;
		}
		break;
	case TAGS:
		if (t->next_id) {
			if (asprintf(&nhref, "index_page=%d&path=%s&page=%d"
			    "&action=tags&commit=%s&headref=%s",
			    qs->index_page, qs->path, qs->page + 1, t->next_id,
			    qs->headref) == -1) {
				error = got_error_from_errno2("%s: asprintf",
				    __func__);
				goto done;
			}
			disp = 1;
		}
		break;
	default:
		disp = 0;
		break;
	}
	if (disp) {
		if (fcgi_gen_response(c, "<a href='?") == -1)
			goto done;
		if (fcgi_gen_response(c, nhref) == -1)
			goto done;
		if (fcgi_gen_response(c, "'>Next</a>") == -1)
			goto done;
	}
	fcgi_gen_response(c, "</div>\n");
done:
	free(t->next_id);
	t->next_id = NULL;
	free(t->prev_id);
	t->prev_id = NULL;
	free(phref);
	free(nhref);
	return error;
}

static const struct got_error *
gotweb_render_index(struct request *c)
{
	const struct got_error *error = NULL;
	struct server *srv = c->srv;
	struct transport *t = c->t;
	struct querystring *qs = t->qs;
	struct repo_dir *repo_dir = NULL;
	DIR *d;
	struct dirent **sd_dent;
	char *c_path = NULL;
	struct stat st;
	unsigned int d_cnt, d_i, d_disp = 0;

	d = opendir(srv->repos_path);
	if (d == NULL) {
		error = got_error_from_errno2("opendir", srv->repos_path);
		return error;
	}

	d_cnt = scandir(srv->repos_path, &sd_dent, NULL, alphasort);
	if (d_cnt == -1) {
		error = got_error_from_errno2("scandir", srv->repos_path);
		goto done;
	}

	/* get total count of repos */
	for (d_i = 0; d_i < d_cnt; d_i++) {
		if (strcmp(sd_dent[d_i]->d_name, ".") == 0 ||
		    strcmp(sd_dent[d_i]->d_name, "..") == 0)
			continue;

		if (asprintf(&c_path, "%s/%s", srv->repos_path,
		    sd_dent[d_i]->d_name) == -1) {
			error = got_error_from_errno("asprintf");
			return error;
		}

		if (lstat(c_path, &st) == 0 && S_ISDIR(st.st_mode) &&
		    !got_path_dir_is_empty(c_path))
		t->repos_total++;
		free(c_path);
		c_path = NULL;
	}

	if (fcgi_gen_response(c, "<div id='index_header'>\n") == -1)
		goto done;
	if (fcgi_gen_response(c,
	    "<div id='index_header_project'>Project</div>\n") == -1)
		goto done;
	if (srv->show_repo_description)
		if (fcgi_gen_response(c, "<div id='index_header_description'>"
		    "Description</div>\n") == -1)
			goto done;
	if (srv->show_repo_owner)
		if (fcgi_gen_response(c, "<div id='index_header_owner'>"
		    "Owner</div>\n") == -1)
			goto done;
	if (srv->show_repo_age)
		if (fcgi_gen_response(c, "<div id='index_header_age'>"
		    "Last Change</div>\n") == -1)
			goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	for (d_i = 0; d_i < d_cnt; d_i++) {
		if (srv->max_repos > 0 && (d_i - 2) == srv->max_repos)
			break; /* account for parent and self */

		if (strcmp(sd_dent[d_i]->d_name, ".") == 0 ||
		    strcmp(sd_dent[d_i]->d_name, "..") == 0)
			continue;

		if (qs->index_page > 0 && (qs->index_page *
		    srv->max_repos_display) > t->prev_disp) {
			t->prev_disp++;
			continue;
		}

		error = gotweb_init_repo_dir(&repo_dir, sd_dent[d_i]->d_name);
		if (error)
			goto done;

		error = gotweb_load_got_path(c, repo_dir);
		if (error && error->code == GOT_ERR_NOT_GIT_REPO) {
			error = NULL;
			continue;
		}
		else if (error && error->code != GOT_ERR_LONELY_PACKIDX)
			goto done;

		if (lstat(repo_dir->path, &st) == 0 &&
		    S_ISDIR(st.st_mode) &&
		    !got_path_dir_is_empty(repo_dir->path))
			goto render;
		else {
			gotweb_free_repo_dir(repo_dir);
			repo_dir = NULL;
			continue;
		}
render:
		d_disp++;
		t->prev_disp++;
		if (fcgi_gen_response(c, "<div class='index_wrapper'>\n") == -1)
			goto done;
		if (fcgi_gen_response(c, "<div class='index_project'>") == -1)
			goto done;

		if (fcgi_gen_response(c, "<a href='?index_page=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->index_page_str) == -1)
			goto done;
		if (fcgi_gen_response(c, "&path=") == -1)
			goto done;
		if (fcgi_gen_response(c, repo_dir->name) == -1)
			goto done;
		if (fcgi_gen_response(c, "&action=summary'>") == -1)
			goto done;
		if (fcgi_gen_response(c, repo_dir->name) == -1)
			goto done;
		if (fcgi_gen_response(c, "</a>") == -1)
			goto done;

		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;

		if (srv->show_repo_description) {
			if (fcgi_gen_response(c,
			    "<div class='index_project_description'>\n") == -1)
				goto done;
			if (fcgi_gen_response(c, repo_dir->description) == -1)
				goto done;
			if (fcgi_gen_response(c, "</div>\n") == -1)
				goto done;
		}

		if (srv->show_repo_owner) {
			if (fcgi_gen_response(c,
			    "<div class='index_project_owner'>") == -1)
				goto done;
			if (fcgi_gen_response(c, repo_dir->owner) == -1)
				goto done;
			if (fcgi_gen_response(c, "</div>\n") == -1)
				goto done;
		}

		if (srv->show_repo_age) {
			if (fcgi_gen_response(c,
			    "<div class='index_project_age'>") == -1)
				goto done;
			if (fcgi_gen_response(c, repo_dir->age) == -1)
				goto done;
			if (fcgi_gen_response(c, "</div>\n") == -1)
				goto done;
		}

		if (fcgi_gen_response(c, "<div class='navs_wrapper'>") == -1)
			goto done;
		if (fcgi_gen_response(c, "<div class='navs'>") == -1)
			goto done;;

		if (fcgi_gen_response(c, "<a href='?index_page=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->index_page_str) == -1)
			goto done;
		if (fcgi_gen_response(c, "&path=") == -1)
			goto done;
		if (fcgi_gen_response(c, repo_dir->name) == -1)
			goto done;
		if (fcgi_gen_response(c, "&action=summary'>") == -1)
			goto done;
		if (fcgi_gen_response(c, "summary") == -1)
			goto done;
		if (fcgi_gen_response(c, "</a> | ") == -1)
			goto done;

		if (fcgi_gen_response(c, "<a href='?index_page=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->index_page_str) == -1)
			goto done;
		if (fcgi_gen_response(c, "&path=") == -1)
			goto done;
		if (fcgi_gen_response(c, repo_dir->name) == -1)
			goto done;
		if (fcgi_gen_response(c, "&action=briefs'>") == -1)
			goto done;
		if (fcgi_gen_response(c, "commit briefs") == -1)
			goto done;
		if (fcgi_gen_response(c, "</a> | ") == -1)
			goto done;

		if (fcgi_gen_response(c, "<a href='?index_page=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->index_page_str) == -1)
			goto done;
		if (fcgi_gen_response(c, "&path=") == -1)
			goto done;
		if (fcgi_gen_response(c, repo_dir->name) == -1)
			goto done;
		if (fcgi_gen_response(c, "&action=commits'>") == -1)
			goto done;
		if (fcgi_gen_response(c, "commits") == -1)
			goto done;
		if (fcgi_gen_response(c, "</a> | ") == -1)
			goto done;

		if (fcgi_gen_response(c, "<a href='?index_page=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->index_page_str) == -1)
			goto done;
		if (fcgi_gen_response(c, "&path=") == -1)
			goto done;
		if (fcgi_gen_response(c, repo_dir->name) == -1)
			goto done;
		if (fcgi_gen_response(c, "&action=tags'>") == -1)
			goto done;
		if (fcgi_gen_response(c, "tags") == -1)
			goto done;
		if (fcgi_gen_response(c, "</a> | ") == -1)
			goto done;

		if (fcgi_gen_response(c, "<a href='?index_page=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->index_page_str) == -1)
			goto done;
		if (fcgi_gen_response(c, "&path=") == -1)
			goto done;
		if (fcgi_gen_response(c, repo_dir->name) == -1)
			goto done;
		if (fcgi_gen_response(c, "&action=tree'>") == -1)
			goto done;
		if (fcgi_gen_response(c, "tree") == -1)
			goto done;
		if (fcgi_gen_response(c, "</a>") == -1)
			goto done;

		if (fcgi_gen_response(c, "</div>") == -1)
			goto done;
		if (fcgi_gen_response(c,
		    "<div class='dotted_line'></div>\n") == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;

		gotweb_free_repo_dir(repo_dir);
		repo_dir = NULL;
		error = got_repo_close(t->repo);
		if (error)
			goto done;
		t->next_disp++;
		if (d_disp == srv->max_repos_display)
			break;
	}
	if (srv->max_repos_display == 0)
		goto div;
	if (srv->max_repos > 0 && srv->max_repos < srv->max_repos_display)
		goto div;
	if (t->repos_total <= srv->max_repos ||
	    t->repos_total <= srv->max_repos_display)
		goto div;

	error = gotweb_render_navs(c);
	if (error)
		goto done;
div:
	fcgi_gen_response(c, "</div>\n");
done:
	if (d != NULL && closedir(d) == EOF && error == NULL)
		error = got_error_from_errno("closedir");
	return error;
}

static const struct got_error *
gotweb_render_blame(struct request *c)
{
	const struct got_error *error = NULL;
	struct transport *t = c->t;
	struct repo_commit *rc = NULL;
	char *age = NULL;

	error = got_get_repo_commits(c, 1);
	if (error)
		return error;

	rc = TAILQ_FIRST(&t->repo_commits);

	error = gotweb_get_time_str(&age, rc->committer_time, TM_LONG);
	if (error)
		goto done;

	if (fcgi_gen_response(c, "<div id='blame_title_wrapper'>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='blame_title'>Blame</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div id='blame_content'>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div id='blame_header_wrapper'>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='blame_header'>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div class='header_age_title'>Date:"
	    "</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div class='header_age'>") == -1)
		goto done;
	if (fcgi_gen_response(c, age ? age : "") == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div id='header_commit_msg_title'>Message:"
	    "</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='header_commit_msg'>") == -1)
		goto done;
	if (fcgi_gen_response(c, rc->commit_msg) == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div class='dotted_line'></div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='blame'>\n") == -1)
		goto done;

	error = got_output_file_blame(c);
	if (error)
		goto done;

	fcgi_gen_response(c, "</div>\n");
done:
	fcgi_gen_response(c, "</div>\n");
	return error;
}

static const struct got_error *
gotweb_render_briefs(struct request *c)
{
	const struct got_error *error = NULL;
	struct repo_commit *rc = NULL;
	struct server *srv = c->srv;
	struct transport *t = c->t;
	struct querystring *qs = t->qs;
	struct repo_dir *repo_dir = t->repo_dir;
	char *smallerthan, *newline;
	char *age = NULL;

	if (fcgi_gen_response(c, "<div id='briefs_title_wrapper'>\n") == -1)
		goto done;
	if (fcgi_gen_response(c,
	    "<div id='briefs_title'>Commit Briefs</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div id='briefs_content'>\n") == -1)
		goto done;

	if (qs->action == SUMMARY) {
		qs->action = BRIEFS;
		error = got_get_repo_commits(c, D_MAXSLCOMMDISP);
	} else
		error = got_get_repo_commits(c, srv->max_commits_display);
	if (error)
		goto done;

	TAILQ_FOREACH(rc, &t->repo_commits, entry) {
		error = gotweb_get_time_str(&age, rc->committer_time, TM_DIFF);
		if (error)
			goto done;
		if (fcgi_gen_response(c, "<div class='briefs_age'>") == -1)
			goto done;
		if (fcgi_gen_response(c, age ? age : "") == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;

		if (fcgi_gen_response(c, "<div class='briefs_author'>") == -1)
			goto done;
		smallerthan = strchr(rc->author, '<');
		if (smallerthan)
			*smallerthan = '\0';
		if (fcgi_gen_response(c, rc->author) == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;

		if (fcgi_gen_response(c, "<div class='briefs_log'>") == -1)
			goto done;
		newline = strchr(rc->commit_msg, '\n');
		if (newline)
			*newline = '\0';

		if (fcgi_gen_response(c, "<a href='?index_page=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->index_page_str) == -1)
			goto done;
		if (fcgi_gen_response(c, "&path=") == -1)
			goto done;
		if (fcgi_gen_response(c, repo_dir->name) == -1)
			goto done;
		if (fcgi_gen_response(c, "&action=diff&commit=") == -1)
			goto done;
		if (fcgi_gen_response(c, rc->commit_id) == -1)
			goto done;
		if (fcgi_gen_response(c, "&headref=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->headref) == -1)
			goto done;
		if (fcgi_gen_response(c, "'>") == -1)
			goto done;
		if (fcgi_gen_response(c, rc->commit_msg) == -1)
			goto done;
		if (fcgi_gen_response(c, "</a>") == -1)
			goto done;
		if (rc->refs_str) {
			if (fcgi_gen_response(c,
			    " <span class='refs_str'>(") == -1)
				goto done;
			if (fcgi_gen_response(c, rc->refs_str) == -1)
				goto done;
			if (fcgi_gen_response(c, ")</span>") == -1)
				goto done;
		}
		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;

		if (fcgi_gen_response(c, "<div class='navs_wrapper'>\n") == -1)
			goto done;
		if (fcgi_gen_response(c, "<div class='navs'>") == -1)
			goto done;
		if (fcgi_gen_response(c, "<a href='?index_page=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->index_page_str) == -1)
			goto done;
		if (fcgi_gen_response(c, "&path=") == -1)
			goto done;
		if (fcgi_gen_response(c, repo_dir->name) == -1)
			goto done;
		if (fcgi_gen_response(c, "&action=diff&commit=") == -1)
			goto done;
		if (fcgi_gen_response(c, rc->commit_id) == -1)
			goto done;
		if (fcgi_gen_response(c, "&headref=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->headref) == -1)
			goto done;
		if (fcgi_gen_response(c, "'>") == -1)
			goto done;
		if (fcgi_gen_response(c, "diff") == -1)
			goto done;
		if (fcgi_gen_response(c, "</a>") == -1)
			goto done;

		if (fcgi_gen_response(c, " | ") == -1)
			goto done;

		if (fcgi_gen_response(c, "<a href='?index_page=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->index_page_str) == -1)
			goto done;
		if (fcgi_gen_response(c, "&path=") == -1)
			goto done;
		if (fcgi_gen_response(c, repo_dir->name) == -1)
			goto done;
		if (fcgi_gen_response(c, "&action=tree&commit=") == -1)
			goto done;
		if (fcgi_gen_response(c, rc->commit_id) == -1)
			goto done;
		if (fcgi_gen_response(c, "&headref=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->headref) == -1)
			goto done;
		if (fcgi_gen_response(c, "'>") == -1)
			goto done;
		if (fcgi_gen_response(c, "tree") == -1)
			goto done;
		if (fcgi_gen_response(c, "</a>") == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;
		if (fcgi_gen_response(c,
		    "<div class='dotted_line'></div>\n") == -1)
			goto done;

		free(age);
		age = NULL;
	}

	if (t->next_id || t->prev_id) {
		error = gotweb_render_navs(c);
		if (error)
			goto done;
	}
	fcgi_gen_response(c, "</div>\n");
done:
	free(age);
	return error;
}

static const struct got_error *
gotweb_render_commits(struct request *c)
{
	const struct got_error *error = NULL;
	struct repo_commit *rc = NULL;
	struct server *srv = c->srv;
	struct transport *t = c->t;
	struct querystring *qs = t->qs;
	struct repo_dir *repo_dir = t->repo_dir;
	char *age = NULL, *author = NULL;
	/* int commit_found = 0; */

	if (fcgi_gen_response(c, "<div class='commits_title_wrapper'>\n") == -1)
		goto done;
	if (fcgi_gen_response(c,
	    "<div class='commits_title'>Commits</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div class='commits_content'>\n") == -1)
		goto done;

	error = got_get_repo_commits(c, srv->max_commits_display);
	if (error)
		goto done;

	TAILQ_FOREACH(rc, &t->repo_commits, entry) {
		error = gotweb_get_time_str(&age, rc->committer_time, TM_LONG);
		if (error)
			goto done;
		error = gotweb_escape_html(&author, rc->author);
		if (error)
			goto done;

		if (fcgi_gen_response(c,
		    "<div class='commits_header_wrapper'>\n") == -1)
			goto done;
		if (fcgi_gen_response(c, "<div class='commits_header'>\n") == -1)
			goto done;


		if (fcgi_gen_response(c, "<div class='header_commit_title'>Commit:"
		    "</div>\n") == -1)
			goto done;
		if (fcgi_gen_response(c, "<div class='header_commit'>") == -1)
			goto done;
		if (fcgi_gen_response(c, rc->commit_id) == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;

		if (fcgi_gen_response(c, "<div class='header_author_title'>Author:"
		    "</div>\n") == -1)
			goto done;
		if (fcgi_gen_response(c, "<div class='header_author'>") == -1)
			goto done;
		if (fcgi_gen_response(c, author ? author : "") == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;

		if (fcgi_gen_response(c, "<div class='header_age_title'>Date:"
		    "</div>\n") == -1)
			goto done;
		if (fcgi_gen_response(c, "<div class='header_age'>") == -1)
			goto done;
		if (fcgi_gen_response(c, age ? age : "") == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;

		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;

		if (fcgi_gen_response(c,
		    "<div class='dotted_line'></div>\n") == -1)
			goto done;
		if (fcgi_gen_response(c, "<div class='commit'>\n") == -1)
			goto done;

		if (fcgi_gen_response(c, rc->commit_msg) == -1)
			goto done;

		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;

		if (fcgi_gen_response(c, "<div class='navs_wrapper'>\n") == -1)
			goto done;
		if (fcgi_gen_response(c, "<div class='navs'>") == -1)
			goto done;
		if (fcgi_gen_response(c, "<a href='?index_page=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->index_page_str) == -1)
			goto done;
		if (fcgi_gen_response(c, "&path=") == -1)
			goto done;
		if (fcgi_gen_response(c, repo_dir->name) == -1)
			goto done;
		if (fcgi_gen_response(c, "&action=diff&commit=") == -1)
			goto done;
		if (fcgi_gen_response(c, rc->commit_id) == -1)
			goto done;
		if (fcgi_gen_response(c, "'>") == -1)
			goto done;
		if (fcgi_gen_response(c, "diff") == -1)
			goto done;
		if (fcgi_gen_response(c, "</a>") == -1)
			goto done;

		if (fcgi_gen_response(c, " | ") == -1)
			goto done;

		if (fcgi_gen_response(c, "<a href='?index_page=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->index_page_str) == -1)
			goto done;
		if (fcgi_gen_response(c, "&path=") == -1)
			goto done;
		if (fcgi_gen_response(c, repo_dir->name) == -1)
			goto done;
		if (fcgi_gen_response(c, "&action=tree&commit=") == -1)
			goto done;
		if (fcgi_gen_response(c, rc->commit_id) == -1)
			goto done;
		if (fcgi_gen_response(c, "'>") == -1)
			goto done;
		if (fcgi_gen_response(c, "tree") == -1)
			goto done;
		if (fcgi_gen_response(c, "</a>") == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;
		if (fcgi_gen_response(c,
		    "<div class='dotted_line'></div>\n") == -1)
			goto done;
		free(age);
		age = NULL;
		free(author);
		author = NULL;
	}

	if (t->next_id || t->prev_id) {
		error = gotweb_render_navs(c);
		if (error)
			goto done;
	}
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;
done:
	free(age);
	return error;
}

static const struct got_error *
gotweb_render_branches(struct request *c)
{
	const struct got_error *error = NULL;
	struct got_reflist_head refs;
	struct got_reflist_entry *re;
	struct transport *t = c->t;
	struct querystring *qs = t->qs;
	struct got_repository *repo = t->repo;
	char *age = NULL;

	TAILQ_INIT(&refs);

	error = got_ref_list(&refs, repo, "refs/heads",
	    got_ref_cmp_by_name, NULL);
	if (error)
		goto done;

	if (fcgi_gen_response(c, "<div id='branches_title_wrapper'>\n") == -1)
		goto done;
	if (fcgi_gen_response(c,
	    "<div id='branches_title'>Branches</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div id='branches_content'>\n") == -1)
		goto done;

	TAILQ_FOREACH(re, &refs, entry) {
		char *refname = NULL;

		if (got_ref_is_symbolic(re->ref))
			continue;

		refname = strdup(got_ref_get_name(re->ref));
		if (refname == NULL) {
			error = got_error_from_errno("strdup");
			goto done;
		}
		if (strncmp(refname, "refs/heads/", 11) != 0)
			continue;

		error = got_get_repo_age(&age, c, qs->path, refname,
		    TM_DIFF);
		if (error)
			goto done;

		if (strncmp(refname, "refs/heads/", 11) == 0)
			refname += 11;

		if (fcgi_gen_response(c, "<div class='branches_wrapper'>") == -1)
			goto done;

		if (fcgi_gen_response(c, "<div class='branches_age'>") == -1)
			goto done;
		if (fcgi_gen_response(c, age ? age : "") == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;

		if (fcgi_gen_response(c, "<div class='branches_space'>") == -1)
			goto done;
		if (fcgi_gen_response(c, "&nbsp;") == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;

		if (fcgi_gen_response(c, "<div class='branch'>") == -1)
			goto done;
		if (fcgi_gen_response(c, "<a href='?index_page=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->index_page_str) == -1)
			goto done;
		if (fcgi_gen_response(c, "&path=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->path) == -1)
			goto done;
		if (fcgi_gen_response(c, "&action=summary&headref=") == -1)
			goto done;
		if (fcgi_gen_response(c, refname) == -1)
			goto done;
		if (fcgi_gen_response(c, "'>") == -1)
			goto done;
		if (fcgi_gen_response(c, refname) == -1)
			goto done;
		if (fcgi_gen_response(c, "</a>") == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;

		if (fcgi_gen_response(c, "<div class='navs_wrapper'>\n") == -1)
			goto done;
		if (fcgi_gen_response(c, "<div class='navs'>") == -1)
			goto done;

		if (fcgi_gen_response(c, "<a href='?index_page=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->index_page_str) == -1)
			goto done;
		if (fcgi_gen_response(c, "&path=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->path) == -1)
			goto done;
		if (fcgi_gen_response(c, "&action=summary&headref=") == -1)
			goto done;
		if (fcgi_gen_response(c, refname) == -1)
			goto done;
		if (fcgi_gen_response(c, "'>") == -1)
			goto done;
		if (fcgi_gen_response(c, "summary") == -1)
			goto done;
		if (fcgi_gen_response(c, "</a>") == -1)
			goto done;

		if (fcgi_gen_response(c, " | ") == -1)
			goto done;

		if (fcgi_gen_response(c, "<a href='?index_page=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->index_page_str) == -1)
			goto done;
		if (fcgi_gen_response(c, "&path=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->path) == -1)
			goto done;
		if (fcgi_gen_response(c, "&action=briefs&headref=") == -1)
			goto done;
		if (fcgi_gen_response(c, refname) == -1)
			goto done;
		if (fcgi_gen_response(c, "'>") == -1)
			goto done;
		if (fcgi_gen_response(c, "commit briefs") == -1)
			goto done;
		if (fcgi_gen_response(c, "</a>") == -1)
			goto done;

		if (fcgi_gen_response(c, " | ") == -1)
			goto done;

		if (fcgi_gen_response(c, "<a href='?index_page=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->index_page_str) == -1)
			goto done;
		if (fcgi_gen_response(c, "&path=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->path) == -1)
			goto done;
		if (fcgi_gen_response(c, "&action=commits&headref=") == -1)
			goto done;
		if (fcgi_gen_response(c, refname) == -1)
			goto done;
		if (fcgi_gen_response(c, "'>") == -1)
			goto done;
		if (fcgi_gen_response(c, "commits") == -1)
			goto done;
		if (fcgi_gen_response(c, "</a>") == -1)
			goto done;

		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;

		if (fcgi_gen_response(c,
		    "<div class='dotted_line'></div>\n") == -1)
			goto done;

		/* branches_wrapper */
		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;

		free(age);
		age = NULL;

	}
	fcgi_gen_response(c, "</div>\n");
done:
	return error;
}

static const struct got_error *
gotweb_render_tree(struct request *c)
{
	const struct got_error *error = NULL;
	struct transport *t = c->t;
	struct repo_commit *rc = NULL;
	char *age = NULL;

	error = got_get_repo_commits(c, 1);
	if (error)
		return error;

	rc = TAILQ_FIRST(&t->repo_commits);

	error = gotweb_get_time_str(&age, rc->committer_time, TM_LONG);
	if (error)
		goto done;

	if (fcgi_gen_response(c, "<div id='tree_title_wrapper'>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='tree_title'>Tree</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div id='tree_content'>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div id='tree_header_wrapper'>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='tree_header'>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div id='header_tree_title'>Tree:"
	    "</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='header_tree'>") == -1)
		goto done;
	if (fcgi_gen_response(c, rc->tree_id) == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div class='header_age_title'>Date:"
	    "</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div class='header_age'>") == -1)
		goto done;
	if (fcgi_gen_response(c, age ? age : "") == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div id='header_commit_msg_title'>Message:"
	    "</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='header_commit_msg'>") == -1)
		goto done;
	if (fcgi_gen_response(c, rc->commit_msg) == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div class='dotted_line'></div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='tree'>\n") == -1)
		goto done;

	error = got_output_repo_tree(c);
	if (error)
		goto done;

	fcgi_gen_response(c, "</div>\n");
	fcgi_gen_response(c, "</div>\n");
done:
	return error;
}

static const struct got_error *
gotweb_render_diff(struct request *c)
{
	const struct got_error *error = NULL;
	struct transport *t = c->t;
	struct repo_commit *rc = NULL;
	char *age = NULL, *author = NULL;

	error = got_get_repo_commits(c, 1);
	if (error)
		return error;

	rc = TAILQ_FIRST(&t->repo_commits);

	error = gotweb_get_time_str(&age, rc->committer_time, TM_LONG);
	if (error)
		goto done;
	error = gotweb_escape_html(&author, rc->author);
	if (error)
		goto done;

	if (fcgi_gen_response(c, "<div id='diff_title_wrapper'>\n") == -1)
		goto done;
	if (fcgi_gen_response(c,
	    "<div id='diff_title'>Commit Diff</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div id='diff_content'>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='diff_header_wrapper'>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='diff_header'>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div id='header_diff_title'>Diff:"
	    "</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='header_diff'>") == -1)
		goto done;
	if (fcgi_gen_response(c, rc->parent_id) == -1)
		goto done;
	if (fcgi_gen_response(c, "<br />") == -1)
		goto done;
	if (fcgi_gen_response(c, rc->commit_id) == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div class='header_commit_title'>Commit:"
	    "</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div class='header_commit'>") == -1)
		goto done;
	if (fcgi_gen_response(c, rc->commit_id) == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div id='header_tree_title'>Tree:"
	    "</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='header_tree'>") == -1)
		goto done;
	if (fcgi_gen_response(c, rc->tree_id) == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div class='header_author_title'>Author:"
	    "</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div class='header_author'>") == -1)
		goto done;
	if (fcgi_gen_response(c, author ? author : "") == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div class='header_age_title'>Date:"
	    "</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div class='header_age'>") == -1)
		goto done;
	if (fcgi_gen_response(c, age ? age : "") == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div id='header_commit_msg_title'>Message:"
	    "</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='header_commit_msg'>") == -1)
		goto done;
	if (fcgi_gen_response(c, rc->commit_msg) == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div class='dotted_line'></div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='diff'>\n") == -1)
		goto done;

	error = got_output_repo_diff(c);
	if (error)
		goto done;

	fcgi_gen_response(c, "</div>\n");
done:
	fcgi_gen_response(c, "</div>\n");
	free(age);
	free(author);
	return error;
}

static const struct got_error *
gotweb_render_summary(struct request *c)
{
	const struct got_error *error = NULL;
	struct transport *t = c->t;
	struct server *srv = c->srv;

	if (fcgi_gen_response(c, "<div id='summary_wrapper'>\n") == -1)
		goto done;

	if (!srv->show_repo_description)
		goto owner;

	if (fcgi_gen_response(c, "<div id='description_title'>"
	    "Description:</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='description'>") == -1)
		goto done;
	if (fcgi_gen_response(c, t->repo_dir->description) == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;
owner:
	if (!srv->show_repo_owner)
		goto last_change;

	if (fcgi_gen_response(c, "<div id='repo_owner_title'>"
	    "Owner:</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='repo_owner'>") == -1)
		goto done;
	if (fcgi_gen_response(c, t->repo_dir->owner) == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;
last_change:
	if (!srv->show_repo_age)
		goto clone_url;

	if (fcgi_gen_response(c, "<div id='last_change_title'>"
	    "Last Change:</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='last_change'>") == -1)
		goto done;
	if (fcgi_gen_response(c, t->repo_dir->age) == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;
clone_url:
	if (!srv->show_repo_cloneurl)
		goto content;

	if (fcgi_gen_response(c, "<div id='cloneurl_title'>"
	    "Clone URL:</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='cloneurl'>") == -1)
		goto done;
	if (fcgi_gen_response(c, t->repo_dir->url) == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;
content:
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	error = gotweb_render_briefs(c);
	if (error) {
		log_warnx("%s: %s", __func__, error->msg);
		goto done;
	}

	error = gotweb_render_tags(c);
	if (error) {
		log_warnx("%s: %s", __func__, error->msg);
		goto done;
	}

	error = gotweb_render_branches(c);
	if (error)
		log_warnx("%s: %s", __func__, error->msg);
done:
	return error;
}

static const struct got_error *
gotweb_render_tag(struct request *c)
{
	const struct got_error *error = NULL;
	struct repo_tag *rt = NULL;
	struct transport *t = c->t;
	char *age = NULL, *author = NULL;

	error = got_get_repo_tags(c, 1);
	if (error)
		goto done;

	if (t->tag_count == 0) {
		error = got_error_set_errno(GOT_ERR_BAD_OBJ_ID,
		    "bad commit id");
		goto done;
	}

	rt = TAILQ_LAST(&t->repo_tags, repo_tags_head);

	error = gotweb_get_time_str(&age, rt->tagger_time, TM_LONG);
	if (error)
		goto done;
	error = gotweb_escape_html(&author, rt->tagger);
	if (error)
		goto done;

	if (fcgi_gen_response(c, "<div id='tags_title_wrapper'>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='tags_title'>Tag</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div id='tags_content'>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='tag_header_wrapper'>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='tag_header'>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div class='header_commit_title'>Commit:"
	    "</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div class='header_commit'>") == -1)
		goto done;
	if (fcgi_gen_response(c, rt->commit_id) == -1)
		goto done;

	if (strncmp(rt->tag_name, "refs/", 5) == 0)
		rt->tag_name += 5;

	if (fcgi_gen_response(c, " <span class='refs_str'>(") == -1)
		goto done;
	if (fcgi_gen_response(c, rt->tag_name) == -1)
		goto done;
	if (fcgi_gen_response(c, ")</span>") == -1)
		goto done;

	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div class='header_author_title'>Tagger:"
	    "</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div class='header_author'>") == -1)
		goto done;
	if (fcgi_gen_response(c, author ? author : "") == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div class='header_age_title'>Date:"
	    "</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div class='header_age'>") == -1)
		goto done;
	if (fcgi_gen_response(c, age ? age : "") == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div id='header_commit_msg_title'>Message:"
	    "</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='header_commit_msg'>") == -1)
		goto done;
	if (fcgi_gen_response(c, rt->commit_msg) == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div class='dotted_line'></div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "<div id='tag_commit'>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, rt->tag_commit) == -1)
		goto done;

	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;
	fcgi_gen_response(c, "</div>\n");
done:
	free(age);
	free(author);
	return error;
}

static const struct got_error *
gotweb_render_tags(struct request *c)
{
	const struct got_error *error = NULL;
	struct repo_tag *rt = NULL;
	struct server *srv = c->srv;
	struct transport *t = c->t;
	struct querystring *qs = t->qs;
	struct repo_dir *repo_dir = t->repo_dir;
	char *newline;
	char *age = NULL;
	int commit_found = 0;

	if (qs->action == BRIEFS) {
		qs->action = TAGS;
		error = got_get_repo_tags(c, D_MAXSLCOMMDISP);
	} else
		error = got_get_repo_tags(c, srv->max_commits_display);
	if (error)
		goto done;

	if (fcgi_gen_response(c, "<div id='tags_title_wrapper'>\n") == -1)
		goto done;
	if (fcgi_gen_response(c,
	    "<div id='tags_title'>Tags</div>\n") == -1)
		goto done;
	if (fcgi_gen_response(c, "</div>\n") == -1)
		goto done;

	if (fcgi_gen_response(c, "<div id='tags_content'>\n") == -1)
		goto done;

	if (t->tag_count == 0) {
		if (fcgi_gen_response(c, "<div id='err_content'>") == -1)
			goto done;
		if (fcgi_gen_response(c,
		    "This repository contains no tags\n") == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;
	}

	TAILQ_FOREACH(rt, &t->repo_tags, entry) {
		if (commit_found == 0 && qs->commit != NULL) {
			if (strcmp(qs->commit, rt->commit_id) != 0)
				continue;
			else
				commit_found = 1;
		}
		error = gotweb_get_time_str(&age, rt->tagger_time, TM_DIFF);
		if (error)
			goto done;
		if (fcgi_gen_response(c, "<div class='tag_age'>") == -1)
			goto done;
		if (fcgi_gen_response(c, age ? age : "") == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;

		if (fcgi_gen_response(c, "<div class='tag'>") == -1)
			goto done;
		if (strncmp(rt->tag_name, "refs/tags/", 10) == 0)
			rt->tag_name += 10;
		if (fcgi_gen_response(c, rt->tag_name) == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;

		if (fcgi_gen_response(c, "<div class='tag_log'>") == -1)
			goto done;
		if (rt->tag_commit != NULL) {
			newline = strchr(rt->tag_commit, '\n');
			if (newline)
				*newline = '\0';
		}

		if (fcgi_gen_response(c, "<a href='?index_page=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->index_page_str) == -1)
			goto done;
		if (fcgi_gen_response(c, "&path=") == -1)
			goto done;
		if (fcgi_gen_response(c, repo_dir->name) == -1)
			goto done;
		if (fcgi_gen_response(c, "&action=tag&commit=") == -1)
			goto done;
		if (fcgi_gen_response(c, rt->commit_id) == -1)
			goto done;
		if (fcgi_gen_response(c, "'>") == -1)
			goto done;
		if (rt->tag_commit != NULL &&
		    fcgi_gen_response(c, rt->tag_commit) == -1)
			goto done;
		if (fcgi_gen_response(c, "</a>") == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;

		if (fcgi_gen_response(c, "<div class='navs_wrapper'>\n") == -1)
			goto done;
		if (fcgi_gen_response(c, "<div class='navs'>") == -1)
			goto done;

		if (fcgi_gen_response(c, "<a href='?index_page=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->index_page_str) == -1)
			goto done;
		if (fcgi_gen_response(c, "&path=") == -1)
			goto done;
		if (fcgi_gen_response(c, repo_dir->name) == -1)
			goto done;
		if (fcgi_gen_response(c, "&action=tag&commit=") == -1)
			goto done;
		if (fcgi_gen_response(c, rt->commit_id) == -1)
			goto done;
		if (fcgi_gen_response(c, "'>") == -1)
			goto done;
		if (fcgi_gen_response(c, "tag") == -1)
			goto done;
		if (fcgi_gen_response(c, "</a>") == -1)
			goto done;

		if (fcgi_gen_response(c, " | ") == -1)
			goto done;

		if (fcgi_gen_response(c, "<a href='?index_page=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->index_page_str) == -1)
			goto done;
		if (fcgi_gen_response(c, "&path=") == -1)
			goto done;
		if (fcgi_gen_response(c, repo_dir->name) == -1)
			goto done;
		if (fcgi_gen_response(c, "&action=briefs&commit=") == -1)
			goto done;
		if (fcgi_gen_response(c, rt->commit_id) == -1)
			goto done;
		if (fcgi_gen_response(c, "'>") == -1)
			goto done;
		if (fcgi_gen_response(c, "commit briefs") == -1)
			goto done;
		if (fcgi_gen_response(c, "</a>") == -1)
			goto done;

		if (fcgi_gen_response(c, " | ") == -1)
			goto done;

		if (fcgi_gen_response(c, "<a href='?index_page=") == -1)
			goto done;
		if (fcgi_gen_response(c, qs->index_page_str) == -1)
			goto done;
		if (fcgi_gen_response(c, "&path=") == -1)
			goto done;
		if (fcgi_gen_response(c, repo_dir->name) == -1)
			goto done;
		if (fcgi_gen_response(c, "&action=commits&commit=") == -1)
			goto done;
		if (fcgi_gen_response(c, rt->commit_id) == -1)
			goto done;
		if (fcgi_gen_response(c, "'>") == -1)
			goto done;
		if (fcgi_gen_response(c, "commits") == -1)
			goto done;
		if (fcgi_gen_response(c, "</a>") == -1)
			goto done;

		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;
		if (fcgi_gen_response(c, "</div>\n") == -1)
			goto done;
		if (fcgi_gen_response(c,
		    "<div class='dotted_line'></div>\n") == -1)
			goto done;

		free(age);
		age = NULL;
	}
	if (t->next_id || t->prev_id) {
		error = gotweb_render_navs(c);
		if (error)
			goto done;
	}
	fcgi_gen_response(c, "</div>\n");
done:
	free(age);
	return error;
}

const struct got_error *
gotweb_escape_html(char **escaped_html, const char *orig_html)
{
	const struct got_error *error = NULL;
	struct escape_pair {
		char c;
		const char *s;
	} esc[] = {
		{ '>', "&gt;" },
		{ '<', "&lt;" },
		{ '&', "&amp;" },
		{ '"', "&quot;" },
		{ '\'', "&apos;" },
		{ '\n', "<br />" },
	};
	size_t orig_len, len;
	int i, j, x;

	orig_len = strlen(orig_html);
	len = orig_len;
	for (i = 0; i < orig_len; i++) {
		for (j = 0; j < nitems(esc); j++) {
			if (orig_html[i] != esc[j].c)
				continue;
			len += strlen(esc[j].s) - 1 /* escaped char */;
		}
	}

	*escaped_html = calloc(len + 1 /* NUL */, sizeof(**escaped_html));
	if (*escaped_html == NULL)
		return got_error_from_errno("calloc");

	x = 0;
	for (i = 0; i < orig_len; i++) {
		int escaped = 0;
		for (j = 0; j < nitems(esc); j++) {
			if (orig_html[i] != esc[j].c)
				continue;

			if (strlcat(*escaped_html, esc[j].s, len + 1)
			    >= len + 1) {
				error = got_error(GOT_ERR_NO_SPACE);
				goto done;
			}
			x += strlen(esc[j].s);
			escaped = 1;
			break;
		}
		if (!escaped) {
			(*escaped_html)[x] = orig_html[i];
			x++;
		}
	}
done:
	if (error) {
		free(*escaped_html);
		*escaped_html = NULL;
	} else {
		(*escaped_html)[x] = '\0';
	}

	return error;
}

static const struct got_error *
gotweb_load_got_path(struct request *c, struct repo_dir *repo_dir)
{
	const struct got_error *error = NULL;
	struct socket *sock = c->sock;
	struct server *srv = c->srv;
	struct transport *t = c->t;
	DIR *dt;
	char *dir_test;
	int opened = 0;

	if (asprintf(&dir_test, "%s/%s/%s", srv->repos_path, repo_dir->name,
	    GOTWEB_GIT_DIR) == -1)
		return got_error_from_errno("asprintf");

	dt = opendir(dir_test);
	if (dt == NULL) {
		free(dir_test);
	} else {
		repo_dir->path = strdup(dir_test);
		if (repo_dir->path == NULL) {
			opened = 1;
			error = got_error_from_errno("strdup");
			goto err;
		}
		opened = 1;
		goto done;
	}

	if (asprintf(&dir_test, "%s/%s/%s", srv->repos_path, repo_dir->name,
	    GOTWEB_GOT_DIR) == -1) {
		dir_test = NULL;
		error = got_error_from_errno("asprintf");
		goto err;
	}

	dt = opendir(dir_test);
	if (dt == NULL)
		free(dir_test);
	else {
		opened = 1;
		error = got_error(GOT_ERR_NOT_GIT_REPO);
		goto err;
	}

	if (asprintf(&dir_test, "%s/%s", srv->repos_path,
	    repo_dir->name) == -1) {
		error = got_error_from_errno("asprintf");
		dir_test = NULL;
		goto err;
	}

	repo_dir->path = strdup(dir_test);
	if (repo_dir->path == NULL) {
		opened = 1;
		error = got_error_from_errno("strdup");
		goto err;
	}

	dt = opendir(dir_test);
	if (dt == NULL) {
		error = got_error_path(repo_dir->name, GOT_ERR_NOT_GIT_REPO);
		goto err;
	} else
		opened = 1;
done:
	error = got_repo_open(&t->repo, repo_dir->path, NULL, sock->pack_fds);
	if (error)
		goto err;
	error = gotweb_get_repo_description(&repo_dir->description, srv,
	    repo_dir->path);
	if (error)
		goto err;
	error = got_get_repo_owner(&repo_dir->owner, c, repo_dir->path);
	if (error)
		goto err;
	error = got_get_repo_age(&repo_dir->age, c, repo_dir->path,
	    NULL, TM_DIFF);
	if (error)
		goto err;
	error = gotweb_get_clone_url(&repo_dir->url, srv, repo_dir->path);
err:
	free(dir_test);
	if (opened)
		if (dt != NULL && closedir(dt) == EOF && error == NULL)
			error = got_error_from_errno("closedir");
	return error;
}

static const struct got_error *
gotweb_init_repo_dir(struct repo_dir **repo_dir, const char *dir)
{
	const struct got_error *error;

	*repo_dir = calloc(1, sizeof(**repo_dir));
	if (*repo_dir == NULL)
		return got_error_from_errno("calloc");

	if (asprintf(&(*repo_dir)->name, "%s", dir) == -1) {
		error = got_error_from_errno("asprintf");
		free(*repo_dir);
		*repo_dir = NULL;
		return error;
	}
	(*repo_dir)->owner = NULL;
	(*repo_dir)->description = NULL;
	(*repo_dir)->url = NULL;
	(*repo_dir)->age = NULL;
	(*repo_dir)->path = NULL;

	return NULL;
}

static const struct got_error *
gotweb_get_repo_description(char **description, struct server *srv, char *dir)
{
	const struct got_error *error = NULL;
	FILE *f = NULL;
	char *d_file = NULL;
	unsigned int len;
	size_t n;

	*description = NULL;
	if (srv->show_repo_description == 0)
		return NULL;

	if (asprintf(&d_file, "%s/description", dir) == -1)
		return got_error_from_errno("asprintf");

	f = fopen(d_file, "r");
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

	if (len == 0)
		goto done;

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
gotweb_get_clone_url(char **url, struct server *srv, char *dir)
{
	const struct got_error *error = NULL;
	FILE *f;
	char *d_file = NULL;
	unsigned int len;
	size_t n;

	*url = NULL;

	if (srv->show_repo_cloneurl == 0)
		return NULL;

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
	if (len == 0)
		goto done;

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
	if (f != NULL && fclose(f) == EOF && error == NULL)
		error = got_error_from_errno("fclose");
	free(d_file);
	return error;
}

const struct got_error *
gotweb_get_time_str(char **repo_age, time_t committer_time, int ref_tm)
{
	struct tm tm;
	long long diff_time;
	const char *years = "years ago", *months = "months ago";
	const char *weeks = "weeks ago", *days = "days ago";
	const char *hours = "hours ago",  *minutes = "minutes ago";
	const char *seconds = "seconds ago", *now = "right now";
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
