/*
 * Copyright (c) 2019, 2020 Tracey Emery <tracey@openbsd.org>
 * Copyright (c) 2004, 2005 Esben Norby <norby@openbsd.org>
 * Copyright (c) 2004 Ryan McBride <mcbride@openbsd.org>
 * Copyright (c) 2002, 2003, 2004 Henning Brauer <henning@openbsd.org>
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2001 Daniel Hartmeier.  All rights reserved.
 * Copyright (c) 2001 Theo de Raadt.  All rights reserved.
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

%{
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/queue.h>

#include <ctype.h>
#include <err.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "got_error.h"
#include "gotweb.h"

TAILQ_HEAD(files, file)		 files = TAILQ_HEAD_INITIALIZER(files);
static struct file {
	TAILQ_ENTRY(file)	 entry;
	FILE			*stream;
	char			*name;
	size_t	 		 ungetpos;
	size_t			 ungetsize;
	u_char			*ungetbuf;
	int			 eof_reached;
	int			 lineno;
} *file, *topfile;
static const struct got_error*	pushfile(struct file**, const char *);
int		 popfile(void);
int		 yyparse(void);
int		 yylex(void);
int		 yyerror(const char *, ...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
int		 kw_cmp(const void *, const void *);
int		 lookup(char *);
int		 igetc(void);
int		 lgetc(int);
void		 lungetc(int);
int		 findeol(void);

TAILQ_HEAD(symhead, sym)	 symhead = TAILQ_HEAD_INITIALIZER(symhead);
struct sym {
	TAILQ_ENTRY(sym)	 entry;
	int			 used;
	int			 persist;
	char			*nam;
	char			*val;
};

int	 symset(const char *, const char *, int);
int	 cmdline_symset(char *);
char	*symget(const char *);

const struct got_error* gerror = NULL;
struct gotweb_config		*gw_conf;

typedef struct {
	union {
		int64_t		 number;
		char		*string;
	} v;
	int lineno;
} YYSTYPE;

%}

%token	GOT_WWW_PATH GOT_MAX_REPOS GOT_SITE_NAME GOT_SITE_OWNER GOT_SITE_LINK
%token	GOT_LOGO GOT_LOGO_URL GOT_SHOW_REPO_OWNER GOT_SHOW_REPO_AGE
%token	GOT_SHOW_REPO_DESCRIPTION GOT_MAX_REPOS_DISPLAY GOT_REPOS_PATH
%token	GOT_MAX_COMMITS_DISPLAY ERROR GOT_SHOW_SITE_OWNER
%token	GOT_SHOW_REPO_CLONEURL
%token	<v.string>	STRING
%token	<v.number>	NUMBER
%type	<v.number>	boolean
%%

grammar		: /* empty */
		| grammar '\n'
		| grammar main '\n'
		;

boolean		: STRING {
			if (strcasecmp($1, "true") == 0 ||
			    strcasecmp($1, "on") == 0 ||
			    strcasecmp($1, "yes") == 0)
				$$ = 1;
			else if (strcasecmp($1, "false") == 0 ||
			    strcasecmp($1, "off") == 0 ||
			    strcasecmp($1, "no") == 0)
				$$ = 0;
			else {
				yyerror("invalid boolean value '%s'", $1);
				free($1);
				YYERROR;
			}
			free($1);
		}
		;
main		: GOT_REPOS_PATH STRING {
			gw_conf->got_repos_path = $2;
		}
		| GOT_WWW_PATH STRING {
			gw_conf->got_www_path = $2;
		}
		| GOT_MAX_REPOS NUMBER {
			if ($2 > 0)
				gw_conf->got_max_repos = $2;
		}
		| GOT_SITE_NAME STRING {
			gw_conf->got_site_name = $2;
		}
		| GOT_SITE_OWNER STRING {
			gw_conf->got_site_owner = $2;
		}
		| GOT_SITE_LINK STRING {
			gw_conf->got_site_link = $2;
		}
		| GOT_LOGO STRING {
			gw_conf->got_logo = $2;
		}
		| GOT_LOGO_URL STRING {
			gw_conf->got_logo_url = $2;
		}
		| GOT_SHOW_SITE_OWNER boolean {
			gw_conf->got_show_site_owner = $2;
		}
		| GOT_SHOW_REPO_OWNER boolean {
			gw_conf->got_show_repo_owner = $2;
		}
		| GOT_SHOW_REPO_AGE boolean {
			gw_conf->got_show_repo_age = $2;
		}
		| GOT_SHOW_REPO_DESCRIPTION boolean {
			gw_conf->got_show_repo_description = $2;
		}
		| GOT_SHOW_REPO_CLONEURL boolean {
			gw_conf->got_show_repo_cloneurl = $2;
		}
		| GOT_MAX_REPOS_DISPLAY NUMBER {
			if ($2 > 0)
				gw_conf->got_max_repos_display = $2;
		}
		| GOT_MAX_COMMITS_DISPLAY NUMBER {
			if ($2 > 0)
				gw_conf->got_max_commits_display = $2;
		}
		;
%%

struct keywords {
	const char	*k_name;
	int		 k_val;
};

int
yyerror(const char *fmt, ...)
{
	va_list		 ap;
	char		*msg;
	char		*err = NULL;

	va_start(ap, fmt);
	if (vasprintf(&msg, fmt, ap) == -1) {
		gerror =  got_error_from_errno("vasprintf");
		return 0;
	}
	va_end(ap);
	if (asprintf(&err, "%s:%d: %s", file->name, yylval.lineno, msg) == -1) {
		gerror = got_error_from_errno("asprintf");
		return(0);
	}
	gerror = got_error_msg(GOT_ERR_PARSE_CONFIG, err);
	free(msg);
	return(0);
}

int
kw_cmp(const void *k, const void *e)
{
	return (strcmp(k, ((const struct keywords *)e)->k_name));
}

int
lookup(char *s)
{
	/* This has to be sorted always. */
	static const struct keywords keywords[] = {
		{ "got_logo",			GOT_LOGO },
		{ "got_logo_url",		GOT_LOGO_URL },
		{ "got_max_commits_display",	GOT_MAX_COMMITS_DISPLAY },
		{ "got_max_repos",		GOT_MAX_REPOS },
		{ "got_max_repos_display",	GOT_MAX_REPOS_DISPLAY },
		{ "got_repos_path",		GOT_REPOS_PATH },
		{ "got_show_repo_age",		GOT_SHOW_REPO_AGE },
		{ "got_show_repo_cloneurl",	GOT_SHOW_REPO_CLONEURL },
		{ "got_show_repo_description",	GOT_SHOW_REPO_DESCRIPTION },
		{ "got_show_repo_owner",	GOT_SHOW_REPO_OWNER },
		{ "got_show_site_owner",	GOT_SHOW_SITE_OWNER },
		{ "got_site_link",		GOT_SITE_LINK },
		{ "got_site_name",		GOT_SITE_NAME },
		{ "got_site_owner",		GOT_SITE_OWNER },
		{ "got_www_path",		GOT_WWW_PATH },
	};
	const struct keywords	*p;

	p = bsearch(s, keywords, sizeof(keywords)/sizeof(keywords[0]),
	    sizeof(keywords[0]), kw_cmp);

	if (p)
		return (p->k_val);
	else
		return (STRING);
}

#define START_EXPAND	1
#define DONE_EXPAND	2

static int	expanding;

int
igetc(void)
{
	int	c;

	while (1) {
		if (file->ungetpos > 0)
			c = file->ungetbuf[--file->ungetpos];
		else
			c = getc(file->stream);

		if (c == START_EXPAND)
			expanding = 1;
		else if (c == DONE_EXPAND)
			expanding = 0;
		else
			break;
	}
	return (c);
}

int
lgetc(int quotec)
{
	int		c, next;

	if (quotec) {
		if ((c = igetc()) == EOF) {
			yyerror("reached end of file while parsing "
			    "quoted string");
			if (file == topfile || popfile() == EOF)
				return (EOF);
			return (quotec);
		}
		return (c);
	}

	while ((c = igetc()) == '\\') {
		next = igetc();
		if (next != '\n') {
			c = next;
			break;
		}
		yylval.lineno = file->lineno;
		file->lineno++;
	}

	if (c == EOF) {
		/*
		 * Fake EOL when hit EOF for the first time. This gets line
		 * count right if last line in included file is syntactically
		 * invalid and has no newline.
		 */
		if (file->eof_reached == 0) {
			file->eof_reached = 1;
			return ('\n');
		}
		while (c == EOF) {
			if (file == topfile || popfile() == EOF)
				return (EOF);
			c = igetc();
		}
	}
	return (c);
}

void
lungetc(int c)
{
	if (c == EOF)
		return;

	if (file->ungetpos >= file->ungetsize) {
		void *p = reallocarray(file->ungetbuf, file->ungetsize, 2);
		if (p == NULL)
			err(1, "%s", __func__);
		file->ungetbuf = p;
		file->ungetsize *= 2;
	}
	file->ungetbuf[file->ungetpos++] = c;
}

int
findeol(void)
{
	int	c;

	/* Skip to either EOF or the first real EOL. */
	while (1) {
		c = lgetc(0);
		if (c == '\n') {
			file->lineno++;
			break;
		}
		if (c == EOF)
			break;
	}
	return (ERROR);
}

int
yylex(void)
{
	char	 buf[8096];
	char	*p, *val;
	int	 quotec, next, c;
	int	 token;

top:
	p = buf;
	while ((c = lgetc(0)) == ' ' || c == '\t')
		; /* nothing */

	yylval.lineno = file->lineno;
	if (c == '#')
		while ((c = lgetc(0)) != '\n' && c != EOF)
			; /* nothing */
	if (c == '$' && !expanding) {
		while (1) {
			if ((c = lgetc(0)) == EOF)
				return (0);

			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			if (isalnum(c) || c == '_') {
				*p++ = c;
				continue;
			}
			*p = '\0';
			lungetc(c);
			break;
		}
		val = symget(buf);
		if (val == NULL) {
			yyerror("macro '%s' not defined", buf);
			return (findeol());
		}
		p = val + strlen(val) - 1;
		lungetc(DONE_EXPAND);
		while (p >= val) {
			lungetc((unsigned char)*p);
			p--;
		}
		lungetc(START_EXPAND);
		goto top;
	}

	switch (c) {
	case '\'':
	case '"':
		quotec = c;
		while (1) {
			if ((c = lgetc(quotec)) == EOF)
				return (0);
			if (c == '\n') {
				file->lineno++;
				continue;
			} else if (c == '\\') {
				if ((next = lgetc(quotec)) == EOF)
					return (0);
				if (next == quotec || c == ' ' || c == '\t')
					c = next;
				else if (next == '\n') {
					file->lineno++;
					continue;
				} else
					lungetc(next);
			} else if (c == quotec) {
				*p = '\0';
				break;
			} else if (c == '\0') {
				yyerror("syntax error");
				return (findeol());
			}
			if (p + 1 >= buf + sizeof(buf) - 1) {
				yyerror("string too long");
				return (findeol());
			}
			*p++ = c;
		}
		yylval.v.string = strdup(buf);
		if (yylval.v.string == NULL)
			err(1, "%s", __func__);
		return (STRING);
	}

#define allowed_to_end_number(x) \
	(isspace(x) || x == ')' || x ==',' || x == '/' || x == '}' || x == '=')

	if (c == '-' || isdigit(c)) {
		do {
			*p++ = c;
			if ((size_t)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && isdigit(c));
		lungetc(c);
		if (p == buf + 1 && buf[0] == '-')
			goto nodigits;
		if (c == EOF || allowed_to_end_number(c)) {
			const char *errstr = NULL;

			*p = '\0';
			yylval.v.number = strtonum(buf, LLONG_MIN,
			    LLONG_MAX, &errstr);
			if (errstr) {
				yyerror("\"%s\" invalid number: %s",
				    buf, errstr);
				return (findeol());
			}
			return (NUMBER);
		} else {
nodigits:
			while (p > buf + 1)
				lungetc((unsigned char)*--p);
			c = (unsigned char)*--p;
			if (c == '-')
				return (c);
		}
	}

#define allowed_in_string(x) \
	(isalnum(x) || (ispunct(x) && x != '(' && x != ')' && \
	x != '{' && x != '}' && \
	x != '!' && x != '=' && x != '#' && \
	x != ','))

	if (isalnum(c) || c == ':' || c == '_') {
		do {
			*p++ = c;
			if ((size_t)(p-buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF && (allowed_in_string(c)));
		lungetc(c);
		*p = '\0';
		if ((token = lookup(buf)) == STRING)
			if ((yylval.v.string = strdup(buf)) == NULL)
				err(1, "%s", __func__);
		return (token);
	}
	if (c == '\n') {
		yylval.lineno = file->lineno;
		file->lineno++;
	}
	if (c == EOF)
		return (0);
	return (c);
}

static const struct got_error*
pushfile(struct file **nfile, const char *name)
{
	const struct got_error* error = NULL;

	if (((*nfile) = calloc(1, sizeof(struct file))) == NULL)
		return got_error_from_errno2(__func__, "calloc");
	if (((*nfile)->name = strdup(name)) == NULL) {
		free(*nfile);
		return got_error_from_errno2(__func__, "strdup");
	}
	if (((*nfile)->stream = fopen((*nfile)->name, "re")) == NULL) {
		char *msg = NULL;
		if (asprintf(&msg, "%s", (*nfile)->name) == -1)
			return got_error_from_errno("asprintf");
		error = got_error_msg(GOT_ERR_NO_CONFIG_FILE, msg);
		free((*nfile)->name);
		free((*nfile));
		free(msg);
		return error;
	}
	(*nfile)->lineno = TAILQ_EMPTY(&files) ? 1 : 0;
	(*nfile)->ungetsize = 16;
	(*nfile)->ungetbuf = malloc((*nfile)->ungetsize);
	if ((*nfile)->ungetbuf == NULL) {
		fclose((*nfile)->stream);
		free((*nfile)->name);
		free((*nfile));
		return got_error_from_errno2(__func__, "malloc");
	}
	TAILQ_INSERT_TAIL(&files, (*nfile), entry);
	return error;
}

int
popfile(void)
{
	struct file	*prev = NULL;

	TAILQ_REMOVE(&files, file, entry);
	fclose(file->stream);
	free(file->name);
	free(file->ungetbuf);
	free(file);
	file = prev;
	return (file ? 0 : EOF);
}

const struct got_error*
parse_gotweb_config(struct gotweb_config **gconf, const char *filename)
{
	gw_conf = malloc(sizeof(struct gotweb_config));
	if (gw_conf == NULL) {
		gerror = got_error_from_errno("malloc");
		goto done;
	}
	gw_conf->got_repos_path = strdup(D_GOTPATH);
	if (gw_conf->got_repos_path == NULL) {
		gerror = got_error_from_errno("strdup");
		goto done;
	}
	gw_conf->got_www_path = strdup(D_GOTWWW);
	if (gw_conf->got_www_path == NULL) {
		gerror = got_error_from_errno("strdup");
		goto done;
	}
	gw_conf->got_site_name = strdup(D_SITENAME);
	if (gw_conf->got_site_name == NULL) {
		gerror = got_error_from_errno("strdup");
		goto done;
	}
	gw_conf->got_site_owner = strdup(D_SITEOWNER);
	if (gw_conf->got_site_owner == NULL) {
		gerror = got_error_from_errno("strdup");
		goto done;
	}
	gw_conf->got_site_link = strdup(D_SITELINK);
	if (gw_conf->got_site_link == NULL) {
		gerror = got_error_from_errno("strdup");
		goto done;
	}
	gw_conf->got_logo = strdup(D_GOTLOGO);
	if (gw_conf->got_logo == NULL) {
		gerror = got_error_from_errno("strdup");
		goto done;
	}
	gw_conf->got_logo_url = strdup(D_GOTURL);
	if (gw_conf->got_logo_url == NULL) {
		gerror = got_error_from_errno("strdup");
		goto done;
	}
	gw_conf->got_show_site_owner = D_SHOWSOWNER;
	gw_conf->got_show_repo_owner = D_SHOWROWNER;
	gw_conf->got_show_repo_age = D_SHOWAGE;
	gw_conf->got_show_repo_description = D_SHOWDESC;
	gw_conf->got_show_repo_cloneurl = D_SHOWURL;
	gw_conf->got_max_repos = D_MAXREPO;
	gw_conf->got_max_repos_display = D_MAXREPODISP;
	gw_conf->got_max_commits_display = D_MAXCOMMITDISP;

	/*
	 * We don't require that the gotweb config file exists
	 * So reset gerror if it doesn't exist and goto done.
	 */
	gerror = pushfile(&file, filename);
	if (gerror && gerror->code == GOT_ERR_NO_CONFIG_FILE) {
		gerror = NULL;
		goto done;
	} else if (gerror)
		return gerror;
	topfile = file;

	yyparse();
	popfile();
done:
	*gconf = gw_conf;
	return gerror;
}

int
symset(const char *nam, const char *val, int persist)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (strcmp(nam, sym->nam) == 0)
			break;
	}

	if (sym != NULL) {
		if (sym->persist == 1)
			return (0);
		else {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}
	if ((sym = calloc(1, sizeof(*sym))) == NULL)
		return (-1);

	sym->nam = strdup(nam);
	if (sym->nam == NULL) {
		free(sym);
		return (-1);
	}
	sym->val = strdup(val);
	if (sym->val == NULL) {
		free(sym->nam);
		free(sym);
		return (-1);
	}
	sym->used = 0;
	sym->persist = persist;
	TAILQ_INSERT_TAIL(&symhead, sym, entry);
	return (0);
}

int
cmdline_symset(char *s)
{
	char	*sym, *val;
	int	ret;
	size_t	len;

	if ((val = strrchr(s, '=')) == NULL)
		return (-1);

	len = strlen(s) - strlen(val) + 1;
	if ((sym = malloc(len)) == NULL)
		errx(1, "cmdline_symset: malloc");

	strlcpy(sym, s, len);

	ret = symset(sym, val + 1, 1);
	free(sym);

	return (ret);
}

char *
symget(const char *nam)
{
	struct sym	*sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (strcmp(nam, sym->nam) == 0) {
			sym->used = 1;
			return (sym->val);
		}
	}
	return (NULL);
}
