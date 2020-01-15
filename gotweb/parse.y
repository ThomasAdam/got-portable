/*
 * Copyright (c) 2019 Tracey Emery <tracey@traceyemery.net>
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

#include <ctype.h>
#include <err.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gotweb.h"

TAILQ_HEAD(files, file)		 files = TAILQ_HEAD_INITIALIZER(files);
static struct file {
	TAILQ_ENTRY(file)	 entry;
	FILE			*stream;
	char			*name;
	int			 lineno;
	int			 errors;
	const struct got_error*	 error;
} *file, *topfile;
struct file	*pushfile(const char *);
int		 popfile(void);
int		 yyparse(void);
int		 yylex(void);
int		 yyerror(const char *, ...)
    __attribute__((__format__ (printf, 1, 2)))
    __attribute__((__nonnull__ (1)));
int		 kw_cmp(const void *, const void *);
int		 lookup(char *);
int		 lgetc(int);
int		 lungetc(int);
int		 findeol(void);

static const struct got_error*	 gerror = NULL;
char				*syn_err;

struct gotweb_conf		*gw_conf;

typedef struct {
	union {
		int64_t			 number;
		char			*string;
	} v;
	int lineno;
} YYSTYPE;

%}

%token	GOT_WWW_PATH GOT_MAX_REPOS GOT_SITE_NAME GOT_SITE_OWNER GOT_SITE_LINK
%token	GOT_LOGO GOT_LOGO_URL GOT_SHOW_REPO_OWNER GOT_SHOW_REPO_AGE
%token	GOT_SHOW_REPO_DESCRIPTION GOT_MAX_REPOS_DISPLAY GOT_REPOS_PATH
%token	GOT_MAX_COMMITS_DISPLAY ON ERROR GOT_SHOW_SITE_OWNER
%token	GOT_SHOW_REPO_CLONEURL
%token	<v.string>		STRING
%token	<v.number>		NUMBER
%type	<v.number>		boolean
%%

grammar		: /* empty */
		| grammar '\n'
		| grammar main '\n'
		| grammar error '\n'		{ file->errors++; }
		;

boolean		: STRING			{
			if (strcasecmp($1, "true") == 0 ||
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
		| ON				{ $$ = 1; }
		;

main		: GOT_REPOS_PATH STRING {
			if ((gw_conf->got_repos_path = strdup($2)) == NULL)
				errx(1, "out of memory");
		}
		| GOT_WWW_PATH STRING {
			if ((gw_conf->got_www_path = strdup($2)) == NULL)
				errx(1, "out of memory");
		}
		| GOT_MAX_REPOS NUMBER {
			if ($2 > 0)
				gw_conf->got_max_repos = $2;
		}
		| GOT_SITE_NAME STRING {
				if ((gw_conf->got_site_name = strdup($2)) == NULL)
				errx(1, "out of memory");
		}
		| GOT_SITE_OWNER STRING {
				if ((gw_conf->got_site_owner = strdup($2)) == NULL)
				errx(1, "out of memory");
		}
		| GOT_SITE_LINK STRING {
				if ((gw_conf->got_site_link = strdup($2)) == NULL)
				errx(1, "out of memory");
		}
		| GOT_LOGO STRING {
				if ((gw_conf->got_logo = strdup($2)) == NULL)
				errx(1, "out of memory");
		}
		| GOT_LOGO_URL STRING {
				if ((gw_conf->got_logo_url = strdup($2)) == NULL)
				errx(1, "out of memory");
		}
		| GOT_SHOW_SITE_OWNER boolean {
			gw_conf->got_show_site_owner = $2;
		}
		| GOT_SHOW_REPO_OWNER boolean {
			gw_conf->got_show_repo_owner = $2;
		}
		| GOT_SHOW_REPO_AGE boolean { gw_conf->got_show_repo_age = $2; }
		| GOT_SHOW_REPO_DESCRIPTION boolean {
			gw_conf->got_show_repo_description =	$2;
		}
		| GOT_SHOW_REPO_CLONEURL boolean {
			gw_conf->got_show_repo_cloneurl =	$2;
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
	char		*msg = NULL;
	static char	 err_msg[512];

	file->errors++;
	va_start(ap, fmt);
	if (vasprintf(&msg, fmt, ap) == -1)
		errx(1, "yyerror vasprintf");
	va_end(ap);
	snprintf(err_msg, sizeof(err_msg), "%s:%d: %s", file->name,
	    yylval.lineno, msg);
	gerror = got_error_from_errno2("parse_error", err_msg);

	free(msg);
	return (0);
}

int
kw_cmp(const void *k, const void *e)
{
	return (strcmp(k, ((const struct keywords *)e)->k_name));
}

int
lookup(char *s)
{
	/* this has to be sorted always */
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

#define MAXPUSHBACK	128

u_char	*parsebuf;
int	 parseindex;
u_char	 pushback_buffer[MAXPUSHBACK];
int	 pushback_index = 0;

int
lgetc(int quotec)
{
	int		c, next;

	if (parsebuf) {
		/* Read character from the parsebuffer instead of input. */
		if (parseindex >= 0) {
			c = parsebuf[parseindex++];
			if (c != '\0')
				return (c);
			parsebuf = NULL;
		} else
			parseindex++;
	}

	if (pushback_index)
		return (pushback_buffer[--pushback_index]);

	if (quotec) {
		if ((c = getc(file->stream)) == EOF) {
			yyerror("reached end of file while parsing "
			    "quoted string");
			if (file == topfile || popfile() == EOF)
				return (EOF);
			return (quotec);
		}
		return (c);
	}

	while ((c = getc(file->stream)) == '\\') {
		next = getc(file->stream);
		if (next != '\n') {
			c = next;
			break;
		}
		yylval.lineno = file->lineno;
		file->lineno++;
	}

	while (c == EOF) {
		if (file == topfile || popfile() == EOF)
			return (EOF);
		c = getc(file->stream);
	}
	return (c);
}

int
lungetc(int c)
{
	if (c == EOF)
		return (EOF);
	if (parsebuf) {
		parseindex--;
		if (parseindex >= 0)
			return (c);
	}
	if (pushback_index < MAXPUSHBACK-1)
		return (pushback_buffer[pushback_index++] = c);
	else
		return (EOF);
}

int
findeol(void)
{
	int	c;

	parsebuf = NULL;

	/* skip to either EOF or the first real EOL */
	while (1) {
		if (pushback_index)
			c = pushback_buffer[--pushback_index];
		else
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
	u_char	 buf[8096];
	u_char	*p;
	int	 quotec, next, c;
	int	 token;

	p = buf;
	while ((c = lgetc(0)) == ' ' || c == '\t')
		; /* nothing */

	yylval.lineno = file->lineno;
	if (c == '#')
		while ((c = lgetc(0)) != '\n' && c != EOF)
			; /* nothing */

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
				if (next == quotec || next == ' ' ||
				    next == '\t')
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
			errx(1, "yylex: strdup");
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
				lungetc(*--p);
			c = *--p;
			if (c == '-')
				return (c);
		}
	}

#define allowed_in_string(x) \
	(isalnum(x) || (ispunct(x) && x != '(' && x != ')' && \
	x != '{' && x != '}' && x != '<' && x != '>' && \
	x != '!' && x != '=' && x != '/' && x != '#' && \
	x != ','))

	if (isalnum(c) || c == ':' || c == '_' || c == '*') {
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
				errx(1, "yylex: strdup");
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

struct file *
pushfile(const char *name)
{
	struct file	*nfile;

	if ((nfile = calloc(1, sizeof(struct file))) == NULL) {
		gerror = got_error(GOT_ERR_NO_SPACE);
		return (NULL);
	}
	if ((nfile->name = strdup(name)) == NULL) {
		gerror = got_error(GOT_ERR_NO_SPACE);
		free(nfile);
		return (NULL);
	}
	if ((nfile->stream = fopen(nfile->name, "r")) == NULL) {
		gerror = got_error_from_errno2("parse_conf", nfile->name);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	nfile->lineno = 1;
	TAILQ_INSERT_TAIL(&files, nfile, entry);
	return (nfile);
}

int
popfile(void)
{
	struct file	*prev;

	if ((prev = TAILQ_PREV(file, files, entry)) != NULL)
		prev->errors += file->errors;

	TAILQ_REMOVE(&files, file, entry);
	fclose(file->stream);
	free(file->name);
	free(file);
	file = prev;
	return (file ? 0 : EOF);
}

const struct got_error*
parse_conf(const char *filename, struct gotweb_conf *gconf)
{
	static const struct got_error*	 error = NULL;

	gw_conf = gconf;
	if ((gw_conf->got_repos_path = strdup(D_GOTPATH)) == NULL)
	err(1, "strdup");
	if ((gw_conf->got_www_path = strdup(D_GOTWWW)) == NULL)
	err(1, "strdup");
	if ((gw_conf->got_site_name = strdup(D_SITENAME)) == NULL)
	err(1, "strdup");
	if ((gw_conf->got_site_owner = strdup(D_SITEOWNER)) == NULL)
	err(1, "strdup");
	if ((gw_conf->got_site_link = strdup(D_SITELINK)) == NULL)
	err(1, "strdup");
	if ((gw_conf->got_logo = strdup(D_GOTLOGO)) == NULL)
	err(1, "strdup");
	if ((gw_conf->got_logo_url = strdup(D_GOTURL)) == NULL)
	err(1, "strdup");
	gw_conf->got_show_site_owner = D_SHOWSOWNER;
	gw_conf->got_show_repo_owner = D_SHOWROWNER;
	gw_conf->got_show_repo_age = D_SHOWAGE;
	gw_conf->got_show_repo_description = D_SHOWDESC;
	gw_conf->got_show_repo_cloneurl = D_SHOWURL;
	gw_conf->got_max_repos = D_MAXREPO;
	gw_conf->got_max_repos_display = D_MAXREPODISP;
	gw_conf->got_max_commits_display = D_MAXCOMMITDISP;
	if ((file = pushfile(filename)) == NULL) {
		error = got_error_from_errno2("parse_conf", GOTWEB_CONF);
		goto done;
	}
	topfile = file;

	yyparse();
	popfile();
	if (gerror)
		error = gerror;
done:
	return error;
}
