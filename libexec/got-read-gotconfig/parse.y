/*
 * Copyright (c) 2020, 2021 Tracey Emery <tracey@openbsd.org>
 * Copyright (c) 2020 Stefan Sperling <stsp@openbsd.org>
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

#include <netdb.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "got_compat.h"

#include "got_error.h"
#include "gotconfig.h"

static struct file {
	FILE			*stream;
	const char		*name;
	size_t	 		 ungetpos;
	size_t			 ungetsize;
	u_char			*ungetbuf;
	int			 eof_reached;
	int			 lineno;
} *file;
static const struct got_error*	newfile(struct file**, const char *, int *);
static void	closefile(struct file *);
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
static int	 parseport(char *, long long *);

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

static int	 atoul(char *, u_long *);

static const struct got_error* gerror;
static struct gotconfig_remote_repo *remote;
static struct gotconfig gotconfig;
static const struct got_error* new_remote(struct gotconfig_remote_repo **);
static const struct got_error* new_fetch_config(struct fetch_config **);
static const struct got_error* new_send_config(struct send_config **);

typedef struct {
	union {
		long long	 number;
		char		*string;
		struct node_branch *branch;
		struct node_ref *ref;
	} v;
	int lineno;
} YYSTYPE;

#if defined(__APPLE__) && !defined(YYSTYPE)
#warning "Setting YYSTYPE - is GNU Bison installed?"
#define YYSTYPE YYSTYPE
#endif
%}

%token	ERROR
%token	REMOTE REPOSITORY SERVER PORT PROTOCOL MIRROR_REFERENCES BRANCH
%token	AUTHOR ALLOWED_SIGNERS REVOKED_SIGNERS SIGNER_ID FETCH_ALL_BRANCHES
%token	REFERENCE FETCH SEND
%token	<v.string>	STRING
%token	<v.number>	NUMBER
%type	<v.number>	boolean portplain
%type	<v.string>	numberstring
%type	<v.branch>	branch xbranch branch_list
%type	<v.ref>		ref xref ref_list

%%

grammar		: /* empty */
		| grammar '\n'
		| grammar author '\n'
		| grammar remote '\n'
		| grammar allowed_signers '\n'
		| grammar revoked_signers '\n'
		| grammar signer_id '\n'
		;
boolean		: STRING {
			if (strcasecmp($1, "true") == 0 ||
			    strcasecmp($1, "yes") == 0)
				$$ = 1;
			else if (strcasecmp($1, "false") == 0 ||
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
numberstring	: NUMBER				{
			char	*s;
			if (asprintf(&s, "%lld", $1) == -1) {
				yyerror("string: asprintf");
				YYERROR;
			}
			$$ = s;
		}
		| STRING
		;
portplain	: numberstring	{
			if (parseport($1, &$$) == -1) {
				free($1);
				YYERROR;
			}
			free($1);
		}
		;
branch		: /* empty */				{ $$ = NULL; }
		| xbranch			{ $$ = $1; }
		| '{' optnl branch_list '}'	{ $$ = $3; }
		;
xbranch		: STRING {
			$$ = calloc(1, sizeof(struct node_branch));
			if ($$ == NULL) {
				yyerror("calloc");
				YYERROR;
			}
			$$->branch_name = $1;
			$$->tail = $$;
		}
		;
branch_list	: xbranch optnl			{ $$ = $1; }
		| branch_list comma xbranch optnl {
			$1->tail->next = $3;
			$1->tail = $3;
			$$ = $1;
		}
		;
ref		: /* empty */		{ $$ = NULL; }
		| xref			{ $$ = $1; }
		| '{' optnl ref_list '}'	{ $$ = $3; }
		;
xref		: STRING {
			$$ = calloc(1, sizeof(struct node_ref));
			if ($$ == NULL) {
				yyerror("calloc");
				YYERROR;
			}
			$$->ref_name = $1;
			$$->tail = $$;
		}
		;
ref_list	: xref optnl			{ $$ = $1; }
		| ref_list comma xref optnl {
			$1->tail->next = $3;
			$1->tail = $3;
			$$ = $1;
		}
		;
remoteopts2	: remoteopts2 remoteopts1 nl
		| remoteopts1 optnl
		;
remoteopts1	: REPOSITORY STRING {
			remote->repository = $2;
		}
		| SERVER STRING {
			remote->server = $2;
		}
		| PROTOCOL STRING {
			remote->protocol = $2;
		}
		| MIRROR_REFERENCES boolean {
			remote->mirror_references = $2;
		}
		| FETCH_ALL_BRANCHES boolean {
			remote->fetch_all_branches = $2;
		}
		| PORT portplain {
			remote->port = $2;
		}
		| BRANCH branch {
			remote->branch = $2;
		}
		| REFERENCE ref {
			remote->fetch_ref = $2;
		}
		| FETCH {
			static const struct got_error* error;

			if (remote->fetch_config != NULL) {
				yyerror("fetch block already exists");
				YYERROR;
			}
			error = new_fetch_config(&remote->fetch_config);
			if (error) {
				yyerror("%s", error->msg);
				YYERROR;
			}
		} '{' optnl fetchempty '}'
		| SEND {
			static const struct got_error* error;

			if (remote->send_config != NULL) {
				yyerror("send block already exists");
				YYERROR;
			}
			error = new_send_config(&remote->send_config);
			if (error) {
				yyerror("%s", error->msg);
				YYERROR;
			}
		} '{' optnl sendempty '}'
		;
fetchempty	: /* empty */
		| fetchopts2
		;
fetchopts2	: fetchopts2 fetchopts1 nl
		| fetchopts1 optnl
		;
fetchopts1	: REPOSITORY STRING {
			remote->fetch_config->repository = $2;
		}
		| SERVER STRING {
			remote->fetch_config->server = $2;
		}
		| PROTOCOL STRING {
			remote->fetch_config->protocol = $2;
		}
		| PORT portplain {
			remote->fetch_config->port = $2;
		}
		| BRANCH branch {
			remote->fetch_config->branch = $2;
		}
		;
sendempty	: /* empty */
		| sendopts2
		;
sendopts2	: sendopts2 sendopts1 nl
		| sendopts1 optnl
		;
sendopts1	: REPOSITORY STRING {
			remote->send_config->repository = $2;
		}
		| SERVER STRING {
			remote->send_config->server = $2;
		}
		| PROTOCOL STRING {
			remote->send_config->protocol = $2;
		}
		| PORT portplain {
			remote->send_config->port = $2;
		}
		| BRANCH branch {
			remote->send_config->branch = $2;
		}
		;
remote		: REMOTE STRING {
			static const struct got_error* error;

			error = new_remote(&remote);
			if (error) {
				free($2);
				yyerror("%s", error->msg);
				YYERROR;
			}
			remote->name = $2;
		} '{' optnl remoteopts2 '}' {
			TAILQ_INSERT_TAIL(&gotconfig.remotes, remote, entry);
			gotconfig.nremotes++;
		}
		;
author		: AUTHOR STRING {
			gotconfig.author = $2;
		}
		;
allowed_signers	: ALLOWED_SIGNERS STRING {
			gotconfig.allowed_signers_file = $2;
		}
		;
revoked_signers	: REVOKED_SIGNERS STRING {
			gotconfig.revoked_signers_file = $2;
		}
		;
signer_id	: SIGNER_ID STRING {
			gotconfig.signer_id = $2;
		}
		;
optnl		: '\n' optnl
		| /* empty */
		;
nl		: '\n' optnl
		;
comma		: ','
		| /* empty */
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
	if (asprintf(&err, "%s: line %d: %s", file->name, yylval.lineno,
	    msg) == -1) {
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
		{"allowed_signers",	ALLOWED_SIGNERS},
		{"author",		AUTHOR},
		{"branch",		BRANCH},
		{"fetch",		FETCH},
		{"fetch-all-branches",	FETCH_ALL_BRANCHES}, /* deprecated */
		{"fetch_all_branches",	FETCH_ALL_BRANCHES},
		{"mirror-references",	MIRROR_REFERENCES}, /* deprecated */
		{"mirror_references",	MIRROR_REFERENCES},
		{"port",		PORT},
		{"protocol",		PROTOCOL},
		{"reference",		REFERENCE},
		{"remote",		REMOTE},
		{"repository",		REPOSITORY},
		{"revoked_signers",	REVOKED_SIGNERS},
		{"send",		SEND},
		{"server",		SERVER},
		{"signer_id",		SIGNER_ID},
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
		c = igetc();
		if (c == EOF) {
			yyerror("reached end of file while parsing "
			    "quoted string");
		}
		return (c);
	}

	c = igetc();
	while (c == '\\') {
		next = igetc();
		if (next != '\n') {
			c = next;
			break;
		}
		yylval.lineno = file->lineno;
		file->lineno++;
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

static long long
getservice(char *n)
{
	struct servent	*s;
	u_long		 ulval;

	if (atoul(n, &ulval) == 0) {
		if (ulval == 0 || ulval > 65535) {
			yyerror("illegal port value %lu", ulval);
			return (-1);
		}
		return ulval;
	} else {
		s = getservbyname(n, "tcp");
		if (s == NULL)
			s = getservbyname(n, "udp");
		if (s == NULL) {
			yyerror("unknown port %s", n);
			return (-1);
		}
		return (s->s_port);
	}
}

static int
parseport(char *port, long long *pn)
{
	if ((*pn = getservice(port)) == -1) {
		*pn = 0LL;
		return (-1);
	}
	return (0);
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
	c = lgetc(0);
	while (c == ' ' || c == '\t')
		c = lgetc(0); /* nothing */

	yylval.lineno = file->lineno;
	if (c == '#') {
		c = lgetc(0);
		while (c != '\n' && c != EOF)
			c = lgetc(0); /* nothing */
	}
	if (c == '$' && !expanding) {
		while (1) {
			c = lgetc(0);
			if (c == EOF)
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
			c = lgetc(quotec);
			if (c == EOF)
				return (0);
			if (c == '\n') {
				file->lineno++;
				continue;
			} else if (c == '\\') {
				next = lgetc(quotec);
				if (next == EOF)
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
			c = lgetc(0);
		} while (c != EOF && isdigit(c));
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
			c = lgetc(0);
		} while (c != EOF && (allowed_in_string(c)));
		lungetc(c);
		*p = '\0';
		token = lookup(buf);
		if (token == STRING) {
			yylval.v.string = strdup(buf);
			if (yylval.v.string == NULL)
				err(1, "%s", __func__);
		}
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
newfile(struct file **nfile, const char *filename, int *fd)
{
	const struct got_error* error = NULL;

	(*nfile) = calloc(1, sizeof(struct file));
	if ((*nfile) == NULL)
		return got_error_from_errno("calloc");
	(*nfile)->stream = fdopen(*fd, "r");
	if ((*nfile)->stream == NULL) {
		error = got_error_from_errno("fdopen");
		free((*nfile));
		return error;
	}
	*fd = -1; /* Stream owns the file descriptor now. */
	(*nfile)->name = filename;
	(*nfile)->lineno = 1;
	(*nfile)->ungetsize = 16;
	(*nfile)->ungetbuf = malloc((*nfile)->ungetsize);
	if ((*nfile)->ungetbuf == NULL) {
		error = got_error_from_errno("malloc");
		fclose((*nfile)->stream);
		free((*nfile));
		return error;
	}
	return NULL;
}

static const struct got_error*
new_remote(struct gotconfig_remote_repo **remote)
{
	const struct got_error *error = NULL;

	*remote = calloc(1, sizeof(**remote));
	if (*remote == NULL)
		error = got_error_from_errno("calloc");
	return error;
}

static const struct got_error*
new_fetch_config(struct fetch_config **fetch_config)
{
	const struct got_error *error = NULL;

	*fetch_config = calloc(1, sizeof(**fetch_config));
	if (*fetch_config == NULL)
		error = got_error_from_errno("calloc");
	return error;
}

static const struct got_error*
new_send_config(struct send_config **send_config)
{
	const struct got_error *error = NULL;

	*send_config = calloc(1, sizeof(**send_config));
	if (*send_config == NULL)
		error = got_error_from_errno("calloc");
	return error;
}

static void
closefile(struct file *file)
{
	fclose(file->stream);
	free(file->ungetbuf);
	free(file);
}

const struct got_error *
gotconfig_parse(struct gotconfig **conf, const char *filename, int *fd)
{
	const struct got_error *err = NULL;
	struct sym	*sym, *next;

	*conf = NULL;

	err = newfile(&file, filename, fd);
	if (err)
		return err;

	TAILQ_INIT(&gotconfig.remotes);

	yyparse();
	closefile(file);

	/* Free macros and check which have not been used. */
	TAILQ_FOREACH_SAFE(sym, &symhead, entry, next) {
		if (!sym->persist) {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}

	if (gerror == NULL)
		*conf = &gotconfig;
	return gerror;
}

static void
free_fetch_config(struct fetch_config *fetch_config)
{
	free(remote->fetch_config->repository);
	free(remote->fetch_config->server);
	free(remote->fetch_config->protocol);
	free(remote->fetch_config);
}

static void
free_send_config(struct send_config *send_config)
{
	free(remote->send_config->repository);
	free(remote->send_config->server);
	free(remote->send_config->protocol);
	free(remote->send_config);
}

void
gotconfig_free(struct gotconfig *conf)
{
	struct gotconfig_remote_repo *remote;

	free(conf->author);
	free(conf->allowed_signers_file);
	free(conf->revoked_signers_file);
	free(conf->signer_id);
	while (!TAILQ_EMPTY(&conf->remotes)) {
		remote = TAILQ_FIRST(&conf->remotes);
		TAILQ_REMOVE(&conf->remotes, remote, entry);
		if (remote->fetch_config != NULL)
			free_fetch_config(remote->fetch_config);
		if (remote->send_config != NULL)
			free_send_config(remote->send_config);
		free(remote->name);
		free(remote->repository);
		free(remote->server);
		free(remote->protocol);
		free(remote);
	}
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
	sym = calloc(1, sizeof(*sym));
	if (sym == NULL)
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

	val = strrchr(s, '=');
	if (val == NULL)
		return (-1);

	len = strlen(s) - strlen(val) + 1;
	sym = malloc(len);
	if (sym == NULL)
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

static int
atoul(char *s, u_long *ulvalp)
{
	u_long	 ulval;
	char	*ep;

	errno = 0;
	ulval = strtoul(s, &ep, 0);
	if (s[0] == '\0' || *ep != '\0')
		return (-1);
	if (errno == ERANGE && ulval == ULONG_MAX)
		return (-1);
	*ulvalp = ulval;
	return (0);
}
