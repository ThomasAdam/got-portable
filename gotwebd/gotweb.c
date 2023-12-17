/*
 * Copyright (c) 2016, 2019, 2020-2022 Tracey Emery <tracey@traceyemery.net>
 * Copyright (c) 2015 Mike Larkin <mlarkin@openbsd.org>
 * Copyright (c) 2014 Reyk Floeter <reyk@openbsd.org>
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
#include "got_compat.h"

#include <net/if.h>
#include <netinet/in.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <event.h>
#include <fcntl.h>
#include <imsg.h>
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

#include "gotwebd.h"
#include "tmpl.h"

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
	{ "blobraw",	BLOBRAW },
	{ "briefs",	BRIEFS },
	{ "commits",	COMMITS },
	{ "diff",	DIFF },
	{ "error",	ERR },
	{ "index",	INDEX },
	{ "patch",	PATCH },
	{ "summary",	SUMMARY },
	{ "tag",	TAG },
	{ "tags",	TAGS },
	{ "tree",	TREE },
	{ "rss",	RSS },
};

static const struct got_error *gotweb_init_querystring(struct querystring **);
static const struct got_error *gotweb_parse_querystring(struct querystring **,
    char *);
static const struct got_error *gotweb_assign_querystring(struct querystring **,
    char *, char *);
static int gotweb_render_index(struct template *);
static const struct got_error *gotweb_init_repo_dir(struct repo_dir **,
    const char *);
static const struct got_error *gotweb_load_got_path(struct request *c,
    struct repo_dir *);
static const struct got_error *gotweb_get_repo_description(char **,
    struct server *, const char *, int);
static const struct got_error *gotweb_get_clone_url(char **, struct server *,
    const char *, int);

static void gotweb_free_querystring(struct querystring *);
static void gotweb_free_repo_dir(struct repo_dir *);

struct server *gotweb_get_server(const char *);

static int
gotweb_reply(struct request *c, int status, const char *ctype,
    struct gotweb_url *location)
{
	const char	*csp;

	if (status != 200 && tp_writef(c->tp, "Status: %d\r\n", status) == -1)
		return -1;

	if (location) {
		if (tp_writes(c->tp, "Location: ") == -1 ||
		    gotweb_render_url(c, location) == -1 ||
		    tp_writes(c->tp, "\r\n") == -1)
			return -1;
	}

	csp = "Content-Security-Policy: default-src 'self'; "
	    "script-src 'none'; object-src 'none';\r\n";
	if (tp_writes(c->tp, csp) == -1)
		return -1;

	if (ctype && tp_writef(c->tp, "Content-Type: %s\r\n", ctype) == -1)
		return -1;

	return tp_writes(c->tp, "\r\n");
}

static int
gotweb_reply_file(struct request *c, const char *ctype, const char *file,
    const char *suffix)
{
	int r;

	r = tp_writef(c->tp, "Content-Disposition: attachment; "
	    "filename=%s%s\r\n", file, suffix ? suffix : "");
	if (r == -1)
		return -1;
	return gotweb_reply(c, 200, ctype, NULL);
}

void
gotweb_process_request(struct request *c)
{
	const struct got_error *error = NULL;
	struct server *srv = NULL;
	struct querystring *qs = NULL;
	struct repo_dir *repo_dir = NULL;
	const char *rss_ctype = "application/rss+xml;charset=utf-8";
	const uint8_t *buf;
	size_t len;
	int r, binary = 0;

	/* init the transport */
	error = gotweb_init_transport(&c->t);
	if (error) {
		log_warnx("%s: %s", __func__, error->msg);
		return;
	}
	/* don't process any further if client disconnected */
	if (c->sock->client_status == CLIENT_DISCONNECT)
		return;
	/* get the gotwebd server */
	srv = gotweb_get_server(c->server_name);
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

	if (qs->action == BLAME || qs->action == BLOB ||
	    qs->action == BLOBRAW || qs->action == DIFF ||
	    qs->action == PATCH) {
		if (qs->commit == NULL) {
			error = got_error(GOT_ERR_BAD_QUERYSTRING);
			goto err;
		}
	}

	if (qs->action != INDEX) {
		error = gotweb_init_repo_dir(&repo_dir, qs->path);
		if (error)
			goto err;
		error = gotweb_load_got_path(c, repo_dir);
		c->t->repo_dir = repo_dir;
		if (error && error->code != GOT_ERR_LONELY_PACKIDX)
			goto err;
	}

	if (qs->action == BLOBRAW || qs->action == BLOB) {
		error = got_get_repo_commits(c, 1);
		if (error)
			goto err;

		error = got_open_blob_for_output(&c->t->blob, &c->t->fd,
		    &binary, c, qs->folder, qs->file, qs->commit);
		if (error)
			goto err;
	}

	switch (qs->action) {
	case BLAME:
		error = got_get_repo_commits(c, 1);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		if (gotweb_reply(c, 200, "text/html", NULL) == -1)
			return;
		gotweb_render_page(c->tp, gotweb_render_blame);
		return;
	case BLOB:
		if (binary) {
			struct gotweb_url url = {
				.index_page = -1,
				.page = -1,
				.action = BLOBRAW,
				.path = qs->path,
				.commit = qs->commit,
				.folder = qs->folder,
				.file = qs->file,
			};

			gotweb_reply(c, 302, NULL, &url);
			return;
		}

		if (gotweb_reply(c, 200, "text/html", NULL) == -1)
			return;
		gotweb_render_page(c->tp, gotweb_render_blob);
		return;
	case BLOBRAW:
		if (binary)
			r = gotweb_reply_file(c, "application/octet-stream",
			    qs->file, NULL);
		else
			r = gotweb_reply(c, 200, "text/plain", NULL);
		if (r == -1)
			return;
		if (template_flush(c->tp) == -1)
			return;

		for (;;) {
			error = got_object_blob_read_block(&len, c->t->blob);
			if (error)
				break;
			if (len == 0)
				break;
			buf = got_object_blob_get_read_buf(c->t->blob);
			if (fcgi_write(c, buf, len) == -1)
				break;
		}
		return;
	case BRIEFS:
		error = got_get_repo_commits(c, srv->max_commits_display);
		if (error)
			goto err;
		if (gotweb_reply(c, 200, "text/html", NULL) == -1)
			return;
		gotweb_render_page(c->tp, gotweb_render_briefs);
		return;
	case COMMITS:
		error = got_get_repo_commits(c, srv->max_commits_display);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		if (gotweb_reply(c, 200, "text/html", NULL) == -1)
			return;
		gotweb_render_page(c->tp, gotweb_render_commits);
		return;
	case DIFF:
		error = got_get_repo_commits(c, 1);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		error = got_open_diff_for_output(&c->t->fp, c);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		if (gotweb_reply(c, 200, "text/html", NULL) == -1)
			return;
		gotweb_render_page(c->tp, gotweb_render_diff);
		return;
	case INDEX:
		c->t->nrepos = scandir(srv->repos_path, &c->t->repos, NULL,
		    alphasort);
		if (c->t->nrepos == -1) {
			c->t->repos = NULL;
			error = got_error_from_errno2("scandir",
			    srv->repos_path);
			goto err;
		}
		if (gotweb_reply(c, 200, "text/html", NULL) == -1)
			return;
		gotweb_render_page(c->tp, gotweb_render_index);
		return;
	case PATCH:
		error = got_get_repo_commits(c, 1);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		error = got_open_diff_for_output(&c->t->fp, c);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		if (gotweb_reply(c, 200, "text/plain", NULL) == -1)
			return;
		gotweb_render_patch(c->tp);
		return;
	case RSS:
		error = got_get_repo_tags(c, D_MAXSLCOMMDISP);
		if (error)
			goto err;
		if (gotweb_reply_file(c, rss_ctype, repo_dir->name, ".rss")
		    == -1)
			return;
		gotweb_render_rss(c->tp);
		return;
	case SUMMARY:
		error = got_ref_list(&c->t->refs, c->t->repo, "refs/heads",
		    got_ref_cmp_by_name, NULL);
		if (error) {
			log_warnx("%s: got_ref_list: %s", __func__,
			    error->msg);
			goto err;
		}
		error = got_get_repo_commits(c, D_MAXSLCOMMDISP);
		if (error)
			goto err;
		qs->action = TAGS;
		error = got_get_repo_tags(c, D_MAXSLTAGDISP);
		if (error) {
			log_warnx("%s: got_get_repo_tags: %s", __func__,
			    error->msg);
			goto err;
		}
		qs->action = SUMMARY;
		if (gotweb_reply(c, 200, "text/html", NULL) == -1)
			return;
		gotweb_render_page(c->tp, gotweb_render_summary);
		return;
	case TAG:
		error = got_get_repo_tags(c, 1);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		if (c->t->tag_count == 0) {
			error = got_error_msg(GOT_ERR_BAD_OBJ_ID,
			    "bad commit id");
			goto err;
		}
		if (gotweb_reply(c, 200, "text/html", NULL) == -1)
			return;
		gotweb_render_page(c->tp, gotweb_render_tag);
		return;
	case TAGS:
		error = got_get_repo_tags(c, srv->max_commits_display);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		if (gotweb_reply(c, 200, "text/html", NULL) == -1)
			return;
		gotweb_render_page(c->tp, gotweb_render_tags);
		return;
	case TREE:
		error = got_get_repo_commits(c, 1);
		if (error) {
			log_warnx("%s: %s", __func__, error->msg);
			goto err;
		}
		if (gotweb_reply(c, 200, "text/html", NULL) == -1)
			return;
		gotweb_render_page(c->tp, gotweb_render_tree);
		return;
	case ERR:
	default:
		error = got_error(GOT_ERR_BAD_QUERYSTRING);
	}

err:
	c->t->error = error;
	if (gotweb_reply(c, 400, "text/html", NULL) == -1)
		return;
	gotweb_render_page(c->tp, gotweb_render_error);
}

struct server *
gotweb_get_server(const char *server_name)
{
	struct server *srv;

	/* check against the server name first */
	if (*server_name != '\0')
		TAILQ_FOREACH(srv, &gotwebd_env->servers, entry)
			if (strcmp(srv->name, server_name) == 0)
				return srv;

	/* otherwise, use the first server */
	return TAILQ_FIRST(&gotwebd_env->servers);
};

const struct got_error *
gotweb_init_transport(struct transport **t)
{
	const struct got_error *error = NULL;

	*t = calloc(1, sizeof(**t));
	if (*t == NULL)
		return got_error_from_errno2(__func__, "calloc");

	TAILQ_INIT(&(*t)->repo_commits);
	TAILQ_INIT(&(*t)->repo_tags);
	TAILQ_INIT(&(*t)->refs);

	(*t)->fd = -1;

	return error;
}

static const struct got_error *
gotweb_init_querystring(struct querystring **qs)
{
	const struct got_error *error = NULL;

	*qs = calloc(1, sizeof(**qs));
	if (*qs == NULL)
		return got_error_from_errno2(__func__, "calloc");

	(*qs)->headref = strdup("HEAD");
	if ((*qs)->headref == NULL) {
		free(*qs);
		*qs = NULL;
		return got_error_from_errno2(__func__, "strdup");
	}

	(*qs)->action = INDEX;

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
		return got_error_from_errno2(__func__, "strdup");

	tok1_pair = tok1;
	tok1_end = tok1;

	while (tok1_pair != NULL) {
		strsep(&tok1_end, "&");

		tok2 = strdup(tok1_pair);
		if (tok2 == NULL) {
			free(tok1);
			return got_error_from_errno2(__func__, "strdup");
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

/*
 * Adapted from usr.sbin/httpd/httpd.c url_decode.
 */
static const struct got_error *
gotweb_urldecode(char *url)
{
	char		*p, *q;
	char		 hex[3];
	unsigned long	 x;

	hex[2] = '\0';
	p = q = url;

	while (*p != '\0') {
		switch (*p) {
		case '%':
			/* Encoding character is followed by two hex chars */
			if (!isxdigit((unsigned char)p[1]) ||
			    !isxdigit((unsigned char)p[2]) ||
			    (p[1] == '0' && p[2] == '0'))
				return got_error(GOT_ERR_BAD_QUERYSTRING);

			hex[0] = p[1];
			hex[1] = p[2];

			/*
			 * We don't have to validate "hex" because it is
			 * guaranteed to include two hex chars followed by nul.
			 */
			x = strtoul(hex, NULL, 16);
			*q = (char)x;
			p += 2;
			break;
		default:
			*q = *p;
			break;
		}
		p++;
		q++;
	}
	*q = '\0';

	return NULL;
}

static const struct got_error *
gotweb_assign_querystring(struct querystring **qs, char *key, char *value)
{
	const struct got_error *error = NULL;
	const char *errstr;
	int a_cnt, el_cnt;

	error = gotweb_urldecode(value);
	if (error)
		return error;

	for (el_cnt = 0; el_cnt < nitems(querystring_keys); el_cnt++) {
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
				error = got_error_from_errno2(__func__,
				    "strdup");
				goto done;
			}
			break;
		case RFILE:
			(*qs)->file = strdup(value);
			if ((*qs)->file == NULL) {
				error = got_error_from_errno2(__func__,
				    "strdup");
				goto done;
			}
			break;
		case FOLDER:
			(*qs)->folder = strdup(value);
			if ((*qs)->folder == NULL) {
				error = got_error_from_errno2(__func__,
				    "strdup");
				goto done;
			}
			break;
		case HEADREF:
			free((*qs)->headref);
			(*qs)->headref = strdup(value);
			if ((*qs)->headref == NULL) {
				error = got_error_from_errno2(__func__,
				    "strdup");
				goto done;
			}
			break;
		case INDEX_PAGE:
			if (*value == '\0')
				break;
			(*qs)->index_page = strtonum(value, INT64_MIN,
			    INT64_MAX, &errstr);
			if (errstr) {
				error = got_error_from_errno3(__func__,
				    "strtonum", errstr);
				goto done;
			}
			if ((*qs)->index_page < 0)
				(*qs)->index_page = 0;
			break;
		case PATH:
			(*qs)->path = strdup(value);
			if ((*qs)->path == NULL) {
				error = got_error_from_errno2(__func__,
				    "strdup");
				goto done;
			}
			break;
		case PAGE:
			if (*value == '\0')
				break;
			(*qs)->page = strtonum(value, INT64_MIN,
			    INT64_MAX, &errstr);
			if (errstr) {
				error = got_error_from_errno3(__func__,
				    "strtonum", errstr);
				goto done;
			}
			if ((*qs)->page < 0)
				(*qs)->page = 0;
			break;
		}

		/* entry found */
		break;
	}
done:
	return error;
}

void
gotweb_free_repo_tag(struct repo_tag *rt)
{
	if (rt != NULL) {
		free(rt->commit_id);
		free(rt->tag_name);
		free(rt->tag_commit);
		free(rt->commit_msg);
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
		free(qs->path);
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
		free(repo_dir->path);
	}
	free(repo_dir);
}

void
gotweb_free_transport(struct transport *t)
{
	const struct got_error *err;
	struct repo_commit *rc = NULL, *trc = NULL;
	struct repo_tag *rt = NULL, *trt = NULL;
	int i;

	got_ref_list_free(&t->refs);
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
	free(t->more_id);
	free(t->tags_more_id);
	if (t->blob)
		got_object_blob_close(t->blob);
	if (t->fp) {
		err = got_gotweb_closefile(t->fp);
		if (err)
			log_warnx("%s: got_gotweb_closefile failure: %s",
			    __func__, err->msg);
	}
	if (t->fd != -1 && close(t->fd) == -1)
		log_warn("%s: close", __func__);
	if (t->repos) {
		for (i = 0; i < t->nrepos; ++i)
			free(t->repos[i]);
		free(t->repos);
	}
	if (t->repo)
		got_repo_close(t->repo);
	free(t);
}

void
gotweb_index_navs(struct request *c, struct gotweb_url *prev, int *have_prev,
    struct gotweb_url *next, int *have_next)
{
	struct transport *t = c->t;
	struct querystring *qs = t->qs;
	struct server *srv = c->srv;

	*have_prev = *have_next = 0;

	if (qs->index_page > 0) {
		*have_prev = 1;
		*prev = (struct gotweb_url){
			.action = -1,
			.index_page = qs->index_page - 1,
			.page = -1,
		};
	}
	if (t->next_disp == srv->max_repos_display &&
	    t->repos_total != (qs->index_page + 1) *
	    srv->max_repos_display) {
		*have_next = 1;
		*next = (struct gotweb_url){
			.action = -1,
			.index_page = qs->index_page + 1,
			.page = -1,
		};
	}
}

static int
gotweb_render_index(struct template *tp)
{
	const struct got_error *error = NULL;
	struct request *c = tp->tp_arg;
	struct server *srv = c->srv;
	struct transport *t = c->t;
	struct querystring *qs = t->qs;
	struct repo_dir *repo_dir = NULL;
	struct dirent **sd_dent = t->repos;
	unsigned int d_i, d_disp = 0;
	unsigned int d_skipped = 0;
	int type, r;

	if (gotweb_render_repo_table_hdr(c->tp) == -1)
		return -1;

	for (d_i = 0; d_i < t->nrepos; d_i++) {
		if (srv->max_repos > 0 && t->prev_disp == srv->max_repos)
			break;

		if (strcmp(sd_dent[d_i]->d_name, ".") == 0 ||
		    strcmp(sd_dent[d_i]->d_name, "..") == 0) {
			d_skipped++;
			continue;
		}

		error = got_path_dirent_type(&type, srv->repos_path,
		    sd_dent[d_i]);
		if (error)
			continue;
		if (type != DT_DIR) {
			d_skipped++;
			continue;
		}

		if (qs->index_page > 0 && (qs->index_page *
		    srv->max_repos_display) > t->prev_disp) {
			t->prev_disp++;
			continue;
		}

		error = gotweb_init_repo_dir(&repo_dir, sd_dent[d_i]->d_name);
		if (error)
			continue;

		error = gotweb_load_got_path(c, repo_dir);
		if (error && error->code != GOT_ERR_LONELY_PACKIDX) {
			if (error->code != GOT_ERR_NOT_GIT_REPO)
				log_warnx("%s: %s: %s", __func__,
				    sd_dent[d_i]->d_name, error->msg);
			gotweb_free_repo_dir(repo_dir);
			repo_dir = NULL;
			d_skipped++;
			continue;
		}

		d_disp++;
		t->prev_disp++;

		r = gotweb_render_repo_fragment(c->tp, repo_dir);
		gotweb_free_repo_dir(repo_dir);
		repo_dir = NULL;
		got_repo_close(t->repo);
		t->repo = NULL;
		if (r == -1)
			return -1;

		t->next_disp++;
		if (d_disp == srv->max_repos_display)
			break;
	}
	t->repos_total = t->nrepos - d_skipped;

	if (srv->max_repos_display == 0)
		return 0;
	if (srv->max_repos > 0 && srv->max_repos < srv->max_repos_display)
		return 0;
	if (t->repos_total <= srv->max_repos ||
	    t->repos_total <= srv->max_repos_display)
		return 0;

	if (gotweb_render_navs(c->tp) == -1)
		return -1;

	return 0;
}

static inline int
should_urlencode(int c)
{
	if (c <= ' ' || c >= 127)
		return 1;

	switch (c) {
		/* gen-delim */
	case ':':
	case '/':
	case '?':
	case '#':
	case '[':
	case ']':
	case '@':
		/* sub-delims */
	case '!':
	case '$':
	case '&':
	case '\'':
	case '(':
	case ')':
	case '*':
	case '+':
	case ',':
	case ';':
	case '=':
		/* needed because the URLs are embedded into the HTML */
	case '\"':
		return 1;
	default:
		return 0;
	}
}

static char *
gotweb_urlencode(const char *str)
{
	const char *s;
	char *escaped;
	size_t i, len;
	int a, b;

	len = 0;
	for (s = str; *s; ++s) {
		len++;
		if (should_urlencode(*s))
			len += 2;
	}

	escaped = calloc(1, len + 1);
	if (escaped == NULL)
		return NULL;

	i = 0;
	for (s = str; *s; ++s) {
		if (should_urlencode(*s)) {
			a = (*s & 0xF0) >> 4;
			b = (*s & 0x0F);

			escaped[i++] = '%';
			escaped[i++] = a <= 9 ? ('0' + a) : ('7' + a);
			escaped[i++] = b <= 9 ? ('0' + b) : ('7' + b);
		} else
			escaped[i++] = *s;
	}

	return escaped;
}

const char *
gotweb_action_name(int action)
{
	switch (action) {
	case BLAME:
		return "blame";
	case BLOB:
		return "blob";
	case BLOBRAW:
		return "blobraw";
	case BRIEFS:
		return "briefs";
	case COMMITS:
		return "commits";
	case DIFF:
		return "diff";
	case ERR:
		return "err";
	case INDEX:
		return "index";
	case PATCH:
		return "patch";
	case SUMMARY:
		return "summary";
	case TAG:
		return "tag";
	case TAGS:
		return "tags";
	case TREE:
		return "tree";
	case RSS:
		return "rss";
	default:
		return NULL;
	}
}

int
gotweb_render_url(struct request *c, struct gotweb_url *url)
{
	const char *sep = "?", *action;
	char *tmp;
	int r;

	action = gotweb_action_name(url->action);
	if (action != NULL) {
		if (tp_writef(c->tp, "?action=%s", action) == -1)
			return -1;
		sep = "&";
	}

	if (url->commit) {
		if (tp_writef(c->tp, "%scommit=%s", sep, url->commit) == -1)
			return -1;
		sep = "&";
	}

	if (url->previd) {
		if (tp_writef(c->tp, "%sprevid=%s", sep, url->previd) == -1)
			return -1;
		sep = "&";
	}

	if (url->prevset) {
		if (tp_writef(c->tp, "%sprevset=%s", sep, url->prevset) == -1)
			return -1;
		sep = "&";
	}

	if (url->file) {
		tmp = gotweb_urlencode(url->file);
		if (tmp == NULL)
			return -1;
		r = tp_writef(c->tp, "%sfile=%s", sep, tmp);
		free(tmp);
		if (r == -1)
			return -1;
		sep = "&";
	}

	if (url->folder) {
		tmp = gotweb_urlencode(url->folder);
		if (tmp == NULL)
			return -1;
		r = tp_writef(c->tp, "%sfolder=%s", sep, tmp);
		free(tmp);
		if (r == -1)
			return -1;
		sep = "&";
	}

	if (url->headref) {
		tmp = gotweb_urlencode(url->headref);
		if (tmp == NULL)
			return -1;
		r = tp_writef(c->tp, "%sheadref=%s", sep, url->headref);
		free(tmp);
		if (r == -1)
			return -1;
		sep = "&";
	}

	if (url->index_page != -1) {
		if (tp_writef(c->tp, "%sindex_page=%d", sep,
		    url->index_page) == -1)
			return -1;
		sep = "&";
	}

	if (url->path) {
		tmp = gotweb_urlencode(url->path);
		if (tmp == NULL)
			return -1;
		r = tp_writef(c->tp, "%spath=%s", sep, tmp);
		free(tmp);
		if (r == -1)
			return -1;
		sep = "&";
	}

	if (url->page != -1) {
		if (tp_writef(c->tp, "%spage=%d", sep, url->page) == -1)
			return -1;
		sep = "&";
	}

	return 0;
}

int
gotweb_render_absolute_url(struct request *c, struct gotweb_url *url)
{
	struct template	*tp = c->tp;
	const char	*proto = c->https ? "https" : "http";

	if (tp_writes(tp, proto) == -1 ||
	    tp_writes(tp, "://") == -1 ||
	    tp_htmlescape(tp, c->server_name) == -1 ||
	    tp_htmlescape(tp, c->document_uri) == -1)
		return -1;

	return gotweb_render_url(c, url);
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

	if (asprintf(&dir_test, "%s/%s/%s", srv->repos_path, repo_dir->name,
	    GOTWEB_GIT_DIR) == -1)
		return got_error_from_errno("asprintf");

	dt = opendir(dir_test);
	if (dt == NULL) {
		free(dir_test);
		if (asprintf(&dir_test, "%s/%s", srv->repos_path,
		    repo_dir->name) == -1)
			return got_error_from_errno("asprintf");
		dt = opendir(dir_test);
		if (dt == NULL) {
			free(dir_test);
			return got_error_path(repo_dir->name,
			    GOT_ERR_NOT_GIT_REPO);
		}
	}

	repo_dir->path = dir_test;
	dir_test = NULL;

	if (srv->respect_exportok &&
	    faccessat(dirfd(dt), "git-daemon-export-ok", F_OK, 0) == -1) {
		error = got_error_path(repo_dir->name, GOT_ERR_NOT_GIT_REPO);
		goto err;
	}

	error = got_repo_open(&t->repo, repo_dir->path, NULL, sock->pack_fds);
	if (error)
		goto err;
	error = gotweb_get_repo_description(&repo_dir->description, srv,
	    repo_dir->path, dirfd(dt));
	if (error)
		goto err;
	error = got_get_repo_owner(&repo_dir->owner, c);
	if (error)
		goto err;
	if (srv->show_repo_age) {
		error = got_get_repo_age(&repo_dir->age, c, NULL);
		if (error)
			goto err;
	}
	error = gotweb_get_clone_url(&repo_dir->url, srv, repo_dir->path,
	    dirfd(dt));
err:
	free(dir_test);
	if (dt != NULL && closedir(dt) == EOF && error == NULL)
		error = got_error_from_errno("closedir");
	if (error && t->repo) {
		got_repo_close(t->repo);
		t->repo = NULL;
	}
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
	(*repo_dir)->path = NULL;

	return NULL;
}

static const struct got_error *
gotweb_get_repo_description(char **description, struct server *srv,
    const char *dirpath, int dir)
{
	const struct got_error *error = NULL;
	struct stat sb;
	int fd = -1;
	off_t len;

	*description = NULL;
	if (srv->show_repo_description == 0)
		return NULL;

	fd = openat(dir, "description", O_RDONLY);
	if (fd == -1) {
		if (errno != ENOENT && errno != EACCES) {
			error = got_error_from_errno_fmt("openat %s/%s",
			    dirpath, "description");
		}
		goto done;
	}

	if (fstat(fd, &sb) == -1) {
		error = got_error_from_errno_fmt("fstat %s/%s",
		    dirpath, "description");
		goto done;
	}

	len = sb.st_size;
	if (len > GOTWEBD_MAXDESCRSZ - 1)
		len = GOTWEBD_MAXDESCRSZ - 1;

	*description = calloc(len + 1, sizeof(**description));
	if (*description == NULL) {
		error = got_error_from_errno("calloc");
		goto done;
	}

	if (read(fd, *description, len) == -1)
		error = got_error_from_errno("read");
done:
	if (fd != -1 && close(fd) == -1 && error == NULL)
		error = got_error_from_errno("close");
	return error;
}

static const struct got_error *
gotweb_get_clone_url(char **url, struct server *srv, const char *dirpath,
    int dir)
{
	const struct got_error *error = NULL;
	struct stat sb;
	int fd = -1;
	off_t len;

	*url = NULL;
	if (srv->show_repo_cloneurl == 0)
		return NULL;

	fd = openat(dir, "cloneurl", O_RDONLY);
	if (fd == -1) {
		if (errno != ENOENT && errno != EACCES) {
			error = got_error_from_errno_fmt("openat %s/%s",
			    dirpath, "cloneurl");
		}
		goto done;
	}

	if (fstat(fd, &sb) == -1) {
		error = got_error_from_errno_fmt("fstat %s/%s",
		    dirpath, "cloneurl");
		goto done;
	}

	len = sb.st_size;
	if (len > GOTWEBD_MAXCLONEURLSZ - 1)
		len = GOTWEBD_MAXCLONEURLSZ - 1;

	*url = calloc(len + 1, sizeof(**url));
	if (*url == NULL) {
		error = got_error_from_errno("calloc");
		goto done;
	}

	if (read(fd, *url, len) == -1)
		error = got_error_from_errno("read");
done:
	if (fd != -1 && close(fd) == -1 && error == NULL)
		error = got_error_from_errno("close");
	return error;
}

int
gotweb_render_age(struct template *tp, time_t committer_time)
{
	struct request *c = tp->tp_arg;
	long long diff_time;
	const char *years = "years ago", *months = "months ago";
	const char *weeks = "weeks ago", *days = "days ago";
	const char *hours = "hours ago",  *minutes = "minutes ago";
	const char *seconds = "seconds ago", *now = "right now";

	diff_time = time(NULL) - committer_time;
	if (diff_time > 60 * 60 * 24 * 365 * 2) {
		if (tp_writef(c->tp, "%lld %s",
		    (diff_time / 60 / 60 / 24 / 365), years) == -1)
			return -1;
	} else if (diff_time > 60 * 60 * 24 * (365 / 12) * 2) {
		if (tp_writef(c->tp, "%lld %s",
		    (diff_time / 60 / 60 / 24 / (365 / 12)),
		    months) == -1)
			return -1;
	} else if (diff_time > 60 * 60 * 24 * 7 * 2) {
		if (tp_writef(c->tp, "%lld %s",
		    (diff_time / 60 / 60 / 24 / 7), weeks) == -1)
			return -1;
	} else if (diff_time > 60 * 60 * 24 * 2) {
		if (tp_writef(c->tp, "%lld %s",
		    (diff_time / 60 / 60 / 24), days) == -1)
			return -1;
	} else if (diff_time > 60 * 60 * 2) {
		if (tp_writef(c->tp, "%lld %s",
		    (diff_time / 60 / 60), hours) == -1)
			return -1;
	} else if (diff_time > 60 * 2) {
		if (tp_writef(c->tp, "%lld %s", (diff_time / 60),
		    minutes) == -1)
			return -1;
	} else if (diff_time > 2) {
		if (tp_writef(c->tp, "%lld %s", diff_time,
		    seconds) == -1)
			return -1;
	} else {
		if (tp_writes(tp, now) == -1)
			return -1;
	}
	return 0;
}
