/*
 * Copyright (c) 2022 Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2016-2019, 2020-2021 Tracey Emery <tracey@traceyemery.net>
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
#include <sys/time.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/stat.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <imsg.h>
#include <limits.h>
#include <pwd.h>
#include <sha1.h>
#include <sha2.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "got_error.h"
#include "got_path.h"
#include "got_reference.h"

#include "log.h"
#include "gotd.h"
#include "auth.h"
#include "listen.h"

TAILQ_HEAD(files, file)		 files = TAILQ_HEAD_INITIALIZER(files);
static struct file {
	TAILQ_ENTRY(file)	 entry;
	FILE			*stream;
	char			*name;
	int			 lineno;
	int			 errors;
} *file;
struct file	*newfile(const char *, int, int);
static void	 closefile(struct file *);
int		 check_file_secrecy(int, const char *);
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

TAILQ_HEAD(symhead, sym)	 symhead = TAILQ_HEAD_INITIALIZER(symhead);
struct sym {
	TAILQ_ENTRY(sym)	 entry;
	int			 used;
	int			 persist;
	char			*nam;
	char			*val;
};

int	 symset(const char *, const char *, int);
char	*symget(const char *);

static int		 errors;

static struct gotd		*gotd;
static struct gotd_repo		*new_repo;
static int			 conf_limit_user_connections(const char *, int);
static struct gotd_repo		*conf_new_repo(const char *);
static void			 conf_new_access_rule(struct gotd_repo *,
				    enum gotd_access, int, char *);
static int			 conf_protect_ref_namespace(char **,
				    struct got_pathlist_head *, char *);
static int			 conf_protect_tag_namespace(struct gotd_repo *,
				    char *);
static int			 conf_protect_branch_namespace(
				    struct gotd_repo *, char *);
static int			 conf_protect_branch(struct gotd_repo *,
				    char *);
static enum gotd_procid		 gotd_proc_id;

typedef struct {
	union {
		long long	 number;
		char		*string;
		struct timeval	 tv;
	} v;
	int lineno;
} YYSTYPE;

%}

%token	PATH ERROR LISTEN ON USER REPOSITORY PERMIT DENY
%token	RO RW CONNECTION LIMIT REQUEST TIMEOUT
%token	PROTECT NAMESPACE BRANCH TAG

%token	<v.string>	STRING
%token	<v.number>	NUMBER
%type	<v.tv>		timeout

%%

grammar		:
		| grammar '\n'
		| grammar main '\n'
		| grammar repository '\n'
		;

timeout		: NUMBER {
			if ($1 < 0) {
				yyerror("invalid timeout: %lld", $1);
				YYERROR;
			}
			$$.tv_sec = $1;
			$$.tv_usec = 0;
		}
		| STRING {
			const char	*errstr;
			const char	*type = "seconds";
			size_t		 len;
			int		 mul = 1;

			if (*$1 == '\0') {
				yyerror("invalid number of seconds: %s", $1);
				free($1);
				YYERROR;
			}

			len = strlen($1);
			switch ($1[len - 1]) {
			case 'S':
			case 's':
				$1[len - 1] = '\0';
				break;
			case 'M':
			case 'm':
				type = "minutes";
				mul = 60;
				$1[len - 1] = '\0';
				break;
			case 'H':
			case 'h':
				type = "hours";
				mul = 60 * 60;
				$1[len - 1] = '\0';
				break;
			}

			$$.tv_usec = 0;
			$$.tv_sec = strtonum($1, 0, INT_MAX / mul, &errstr);
			if (errstr) {
				yyerror("number of %s is %s: %s", type,
				    errstr, $1);
				free($1);
				YYERROR;
			}

			$$.tv_sec *= mul;
			free($1);
		}
		;

main		: LISTEN ON STRING {
			if (!got_path_is_absolute($3))
				yyerror("bad unix socket path \"%s\": "
				    "must be an absolute path", $3);

			if (gotd_proc_id == PROC_LISTEN) {
				if (strlcpy(gotd->unix_socket_path, $3,
				    sizeof(gotd->unix_socket_path)) >=
				    sizeof(gotd->unix_socket_path)) {
					yyerror("%s: unix socket path too long",
					    __func__);
					free($3);
					YYERROR;
				}
			}
			free($3);
		}
		| USER STRING {
			if (strlcpy(gotd->user_name, $2,
			    sizeof(gotd->user_name)) >=
			    sizeof(gotd->user_name)) {
				yyerror("%s: user name too long", __func__);
				free($2);
				YYERROR;
			}
			free($2);
		}
		| connection
		;

connection	: CONNECTION '{' optnl conflags_l '}'
		| CONNECTION conflags

conflags_l	: conflags optnl conflags_l
		| conflags optnl
		;

conflags	: REQUEST TIMEOUT timeout		{
			if ($3.tv_sec <= 0) {
				yyerror("invalid timeout: %lld", $3.tv_sec);
				YYERROR;
			}
			memcpy(&gotd->request_timeout, &$3,
			    sizeof(gotd->request_timeout));
		}
		| LIMIT USER STRING NUMBER	{
			if (gotd_proc_id == PROC_LISTEN &&
			    conf_limit_user_connections($3, $4) == -1) {
				free($3);
				YYERROR;
			}
			free($3);
		}
		;

protect		: PROTECT '{' optnl protectflags_l '}'
		| PROTECT protectflags

protectflags_l	: protectflags optnl protectflags_l
		| protectflags optnl
		;

protectflags	: TAG NAMESPACE STRING {
			if (gotd_proc_id == PROC_GOTD ||
			    gotd_proc_id == PROC_REPO_WRITE) {
				if (conf_protect_tag_namespace(new_repo, $3)) {
					free($3);
					YYERROR;
				}
			}
			free($3);
		}
		| BRANCH NAMESPACE STRING {
			if (gotd_proc_id == PROC_GOTD ||
			    gotd_proc_id == PROC_REPO_WRITE) {
				if (conf_protect_branch_namespace(new_repo,
				    $3)) {
					free($3);
					YYERROR;
				}
			}
			free($3);
		}
		| BRANCH STRING {
			if (gotd_proc_id == PROC_GOTD ||
			    gotd_proc_id == PROC_REPO_WRITE) {
				if (conf_protect_branch(new_repo, $2)) {
					free($2);
					YYERROR;
				}
			}
			free($2);
		}
		;

repository	: REPOSITORY STRING {
			struct gotd_repo *repo;

			TAILQ_FOREACH(repo, &gotd->repos, entry) {
				if (strcmp(repo->name, $2) == 0) {
					yyerror("duplicate repository '%s'", $2);
					free($2);
					YYERROR;
				}
			}

			if (gotd_proc_id == PROC_GOTD ||
			    gotd_proc_id == PROC_AUTH ||
			    gotd_proc_id == PROC_REPO_WRITE ||
			    gotd_proc_id == PROC_GITWRAPPER) {
				new_repo = conf_new_repo($2);
			}
			free($2);
		} '{' optnl repoopts2 '}' {
		}
		;

repoopts1	: PATH STRING {
			if (gotd_proc_id == PROC_GOTD ||
			    gotd_proc_id == PROC_AUTH ||
			    gotd_proc_id == PROC_REPO_WRITE ||
			    gotd_proc_id == PROC_GITWRAPPER) {
				if (!got_path_is_absolute($2)) {
					yyerror("%s: path %s is not absolute",
					    __func__, $2);
					free($2);
					YYERROR;
				}
				if (realpath($2, new_repo->path) == NULL) {
					/*
					 * To give admins a chance to create
					 * missing repositories at run-time
					 * we only warn about ENOENT here.
					 *
					 * And ignore 'permission denied' when
					 * running in gitwrapper. Users may be
					 * able to access this repository via
					 * gotd regardless.
					 */
					if (errno == ENOENT) {
						yyerror("realpath %s: %s", $2,
						    strerror(errno));
					} else if (errno != EACCES ||
					    gotd_proc_id != PROC_GITWRAPPER) {
						yyerror("realpath %s: %s", $2,
						    strerror(errno));
						free($2);
						YYERROR;
					}

					if (strlcpy(new_repo->path, $2,
					    sizeof(new_repo->path)) >=
					    sizeof(new_repo->path))
						yyerror("path too long");
				}
			}
			free($2);
		}
		| PERMIT RO STRING {
			if (gotd_proc_id == PROC_AUTH) {
				conf_new_access_rule(new_repo,
				    GOTD_ACCESS_PERMITTED, GOTD_AUTH_READ, $3);
			} else
				free($3);
		}
		| PERMIT RW STRING {
			if (gotd_proc_id == PROC_AUTH) {
				conf_new_access_rule(new_repo,
				    GOTD_ACCESS_PERMITTED,
				    GOTD_AUTH_READ | GOTD_AUTH_WRITE, $3);
			} else
				free($3);
		}
		| DENY STRING {
			if (gotd_proc_id == PROC_AUTH) {
				conf_new_access_rule(new_repo,
				    GOTD_ACCESS_DENIED, 0, $2);
			} else
				free($2);
		}
		| protect
		;

repoopts2	: repoopts2 repoopts1 nl
		| repoopts1 optnl
		;

nl		: '\n' optnl
		;

optnl		: '\n' optnl		/* zero or more newlines */
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
	va_list ap;
	char *msg;

	file->errors++;
	va_start(ap, fmt);
	if (vasprintf(&msg, fmt, ap) == -1)
		fatalx("yyerror vasprintf");
	va_end(ap);
	logit(LOG_CRIT, "%s:%d: %s", file->name, yylval.lineno, msg);
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
	/* This has to be sorted always. */
	static const struct keywords keywords[] = {
		{ "branch",			BRANCH },
		{ "connection",			CONNECTION },
		{ "deny",			DENY },
		{ "limit",			LIMIT },
		{ "listen",			LISTEN },
		{ "namespace",			NAMESPACE },
		{ "on",				ON },
		{ "path",			PATH },
		{ "permit",			PERMIT },
		{ "protect",			PROTECT },
		{ "repository",			REPOSITORY },
		{ "request",			REQUEST },
		{ "ro",				RO },
		{ "rw",				RW },
		{ "tag",			TAG },
		{ "timeout",			TIMEOUT },
		{ "user",			USER },
	};
	const struct keywords *p;

	p = bsearch(s, keywords, sizeof(keywords)/sizeof(keywords[0]),
	    sizeof(keywords[0]), kw_cmp);

	if (p)
		return (p->k_val);
	else
		return (STRING);
}

#define MAXPUSHBACK	128

unsigned char *parsebuf;
int parseindex;
unsigned char pushback_buffer[MAXPUSHBACK];
int pushback_index = 0;

int
lgetc(int quotec)
{
	int c, next;

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
		c = getc(file->stream);
		if (c == EOF)
			yyerror("reached end of file while parsing "
			    "quoted string");
		return (c);
	}

	c = getc(file->stream);
	while (c == '\\') {
		next = getc(file->stream);
		if (next != '\n') {
			c = next;
			break;
		}
		yylval.lineno = file->lineno;
		file->lineno++;
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
	int c;

	parsebuf = NULL;

	/* Skip to either EOF or the first real EOL. */
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
	unsigned char buf[8096];
	unsigned char *p, *val;
	int quotec, next, c;
	int token;

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
	if (c == '$' && parsebuf == NULL) {
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
		parsebuf = val;
		parseindex = 0;
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
			err(1, "yylex: strdup");
		return (STRING);
	}

#define allowed_to_end_number(x) \
	(isspace(x) || x == ')' || x ==',' || x == '/' || x == '}' || x == '=')

	if (c == '-' || isdigit(c)) {
		do {
			*p++ = c;
			if ((unsigned)(p-buf) >= sizeof(buf)) {
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
				lungetc(*--p);
			c = *--p;
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
			if ((unsigned)(p-buf) >= sizeof(buf)) {
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
				err(1, "yylex: strdup");
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

int
check_file_secrecy(int fd, const char *fname)
{
	struct stat st;

	if (fstat(fd, &st)) {
		log_warn("cannot stat %s", fname);
		return (-1);
	}
	if (st.st_uid != 0 && st.st_uid != getuid()) {
		log_warnx("%s: owner not root or current user", fname);
		return (-1);
	}
	if (st.st_mode & (S_IWGRP | S_IXGRP | S_IRWXO)) {
		log_warnx("%s: group writable or world read/writable", fname);
		return (-1);
	}
	return (0);
}

struct file *
newfile(const char *name, int secret, int required)
{
	struct file *nfile;

	nfile = calloc(1, sizeof(struct file));
	if (nfile == NULL) {
		log_warn("calloc");
		return (NULL);
	}
	nfile->name = strdup(name);
	if (nfile->name == NULL) {
		log_warn("strdup");
		free(nfile);
		return (NULL);
	}
	nfile->stream = fopen(nfile->name, "r");
	if (nfile->stream == NULL) {
		if (required)
			log_warn("open %s", nfile->name);
		free(nfile->name);
		free(nfile);
		return (NULL);
	} else if (secret &&
	    check_file_secrecy(fileno(nfile->stream), nfile->name)) {
		fclose(nfile->stream);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	nfile->lineno = 1;
	return (nfile);
}

static void
closefile(struct file *xfile)
{
	fclose(xfile->stream);
	free(xfile->name);
	free(xfile);
}

int
parse_config(const char *filename, enum gotd_procid proc_id,
    struct gotd *env)
{
	struct sym *sym, *next;
	struct gotd_repo *repo;
	int require_config_file = (proc_id != PROC_GITWRAPPER);

	memset(env, 0, sizeof(*env));

	gotd = env;
	gotd_proc_id = proc_id;
	TAILQ_INIT(&gotd->repos);

	/* Apply default values. */
	if (strlcpy(gotd->unix_socket_path, GOTD_UNIX_SOCKET,
	    sizeof(gotd->unix_socket_path)) >= sizeof(gotd->unix_socket_path)) {
		fprintf(stderr, "%s: unix socket path too long", __func__);
		return -1;
	}
	if (strlcpy(gotd->user_name, GOTD_USER,
	    sizeof(gotd->user_name)) >= sizeof(gotd->user_name)) {
		fprintf(stderr, "%s: user name too long", __func__);
		return -1;
	}

	gotd->request_timeout.tv_sec = GOTD_DEFAULT_REQUEST_TIMEOUT;
	gotd->request_timeout.tv_usec = 0;

	file = newfile(filename, 0, require_config_file);
	if (file == NULL)
		return require_config_file ? -1 : 0;

	yyparse();
	errors = file->errors;
	closefile(file);

	/* Free macros and check which have not been used. */
	TAILQ_FOREACH_SAFE(sym, &symhead, entry, next) {
		if ((gotd->verbosity > 1) && !sym->used)
			fprintf(stderr, "warning: macro '%s' not used\n",
			    sym->nam);
		if (!sym->persist) {
			free(sym->nam);
			free(sym->val);
			TAILQ_REMOVE(&symhead, sym, entry);
			free(sym);
		}
	}

	if (errors)
		return (-1);

	TAILQ_FOREACH(repo, &gotd->repos, entry) {
		if (repo->path[0] == '\0') {
			log_warnx("repository \"%s\": no path provided in "
			    "configuration file", repo->name);
			return (-1);
		}
	}

	if (proc_id == PROC_GOTD && TAILQ_EMPTY(&gotd->repos)) {
		log_warnx("no repository defined in configuration file");
		return (-1);
	}

	return (0);
}

static int
uid_connection_limit_cmp(const void *pa, const void *pb)
{
	const struct gotd_uid_connection_limit *a = pa, *b = pb;

	if (a->uid < b->uid)
		return -1;
	else if (a->uid > b->uid);
		return 1;

	return 0;
}

static int
conf_limit_user_connections(const char *user, int maximum)
{
	uid_t uid;
	struct gotd_uid_connection_limit *limit;
	size_t nlimits;

	if (maximum < 1) {
		yyerror("max connections cannot be smaller 1");
		return -1;
	}
	if (maximum > GOTD_MAXCLIENTS) {
		yyerror("max connections must be <= %d", GOTD_MAXCLIENTS);
		return -1;
	}

	if (gotd_parseuid(user, &uid) == -1) {
		yyerror("%s: no such user", user);
		return -1;
	}

	limit = gotd_find_uid_connection_limit(gotd->connection_limits,
	    gotd->nconnection_limits, uid);
	if (limit) {
		limit->max_connections = maximum;
		return 0;
	}

	limit = gotd->connection_limits;
	nlimits = gotd->nconnection_limits + 1;
	limit = reallocarray(limit, nlimits, sizeof(*limit));
	if (limit == NULL)
		fatal("reallocarray");

	limit[nlimits - 1].uid = uid;
	limit[nlimits - 1].max_connections = maximum;

	gotd->connection_limits = limit;
	gotd->nconnection_limits = nlimits;
	qsort(gotd->connection_limits, gotd->nconnection_limits,
	    sizeof(gotd->connection_limits[0]), uid_connection_limit_cmp);

	return 0;
}

static struct gotd_repo *
conf_new_repo(const char *name)
{
	struct gotd_repo *repo;

	if (name[0] == '\0') {
		fatalx("syntax error: empty repository name found in %s",
		    file->name);
	}

	if (strchr(name, '\n') != NULL)
		fatalx("repository names must not contain linefeeds: %s", name);

	repo = calloc(1, sizeof(*repo));
	if (repo == NULL)
		fatalx("%s: calloc", __func__);

	STAILQ_INIT(&repo->rules);
	TAILQ_INIT(&repo->protected_tag_namespaces);
	TAILQ_INIT(&repo->protected_branch_namespaces);
	TAILQ_INIT(&repo->protected_branches);

	if (strlcpy(repo->name, name, sizeof(repo->name)) >=
	    sizeof(repo->name))
		fatalx("%s: strlcpy", __func__);

	TAILQ_INSERT_TAIL(&gotd->repos, repo, entry);
	gotd->nrepos++;

	return repo;
};

static void
conf_new_access_rule(struct gotd_repo *repo, enum gotd_access access,
    int authorization, char *identifier)
{
	struct gotd_access_rule *rule;

	rule = calloc(1, sizeof(*rule));
	if (rule == NULL)
		fatal("calloc");

	rule->access = access;
	rule->authorization = authorization;
	rule->identifier = identifier;

	STAILQ_INSERT_TAIL(&repo->rules, rule, entry);
}

static int
refname_is_valid(char *refname)
{
	if (strncmp(refname, "refs/", 5) != 0) {
		yyerror("reference name must begin with \"refs/\": %s",
		    refname);
		return 0;
	}

	if (!got_ref_name_is_valid(refname)) {
		yyerror("invalid reference name: %s", refname);
		return 0;
	}

	return 1;
}

static int
conf_protect_ref_namespace(char **new, struct got_pathlist_head *refs,
    char *namespace)
{
	const struct got_error *error;
	struct got_pathlist_entry *pe;
	char *s;

	*new = NULL;

	got_path_strip_trailing_slashes(namespace);
	if (!refname_is_valid(namespace))
		return -1;
	if (asprintf(&s, "%s/", namespace) == -1) {
		yyerror("asprintf: %s", strerror(errno));
		return -1;
	}

	error = got_pathlist_insert(&pe, refs, s, NULL);
	if (error || pe == NULL) {
		free(s);
		if (error)
			yyerror("got_pathlist_insert: %s", error->msg);
		else
			yyerror("duplicate protected namespace %s", namespace);
		return -1;
	}

	*new = s;
	return 0;
}

static int
conf_protect_tag_namespace(struct gotd_repo *repo, char *namespace)
{
	struct got_pathlist_entry *pe;
	char *new;

	if (conf_protect_ref_namespace(&new, &repo->protected_tag_namespaces,
	    namespace) == -1)
		return -1;

	TAILQ_FOREACH(pe, &repo->protected_branch_namespaces, entry) {
		if (strcmp(pe->path, new) == 0) {
			yyerror("duplicate protected namespace %s", namespace);
			return -1;
		}
	}

	return 0;
}

static int
conf_protect_branch_namespace(struct gotd_repo *repo, char *namespace)
{
	struct got_pathlist_entry *pe;
	char *new;

	if (conf_protect_ref_namespace(&new,
	    &repo->protected_branch_namespaces, namespace) == -1)
		return -1;

	TAILQ_FOREACH(pe, &repo->protected_tag_namespaces, entry) {
		if (strcmp(pe->path, new) == 0) {
			yyerror("duplicate protected namespace %s", namespace);
			return -1;
		}
	}

	return 0;
}

static int
conf_protect_branch(struct gotd_repo *repo, char *branchname)
{
	const struct got_error *error;
	struct got_pathlist_entry *new;
	char *refname;

	if (strncmp(branchname, "refs/heads/", 11) != 0) {
		if (asprintf(&refname, "refs/heads/%s", branchname) == -1) {
			yyerror("asprintf: %s", strerror(errno));
			return -1;
		}
	} else {
		refname = strdup(branchname);
		if (refname == NULL) {
			yyerror("strdup: %s", strerror(errno));
			return -1;
		}
	}

	if (!refname_is_valid(refname)) {
		free(refname);
		return -1;
	}

	error = got_pathlist_insert(&new, &repo->protected_branches,
	    refname, NULL);
	if (error || new == NULL) {
		free(refname);
		if (error)
			yyerror("got_pathlist_insert: %s", error->msg);
		else
			yyerror("duplicate protect branch %s", branchname);
		return -1;
	}

	return 0;
}

int
symset(const char *nam, const char *val, int persist)
{
	struct sym *sym;

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

char *
symget(const char *nam)
{
	struct sym *sym;

	TAILQ_FOREACH(sym, &symhead, entry) {
		if (strcmp(nam, sym->nam) == 0) {
			sym->used = 1;
			return (sym->val);
		}
	}
	return (NULL);
}

struct gotd_repo *
gotd_find_repo_by_name(const char *repo_name, struct gotd *gotd)
{
	struct gotd_repo *repo;
	size_t namelen;

	TAILQ_FOREACH(repo, &gotd->repos, entry) {
		namelen = strlen(repo->name);
		if (strncmp(repo->name, repo_name, namelen) != 0)
			continue;
		if (repo_name[namelen] == '\0' ||
		    strcmp(&repo_name[namelen], ".git") == 0)
			return repo;
	}

	return NULL;
}

struct gotd_repo *
gotd_find_repo_by_path(const char *repo_path, struct gotd *gotd)
{
	struct gotd_repo *repo;

	TAILQ_FOREACH(repo, &gotd->repos, entry) {
		if (strcmp(repo->path, repo_path) == 0)
			return repo;
	}

	return NULL;
}

struct gotd_uid_connection_limit *
gotd_find_uid_connection_limit(struct gotd_uid_connection_limit *limits,
    size_t nlimits, uid_t uid)
{
	/* This array is always sorted to allow for binary search. */
	int i, left = 0, right = nlimits - 1;

	while (left <= right) {
		i = ((left + right) / 2);
		if (limits[i].uid == uid)
			return &limits[i];
		if (limits[i].uid > uid)
			left = i + 1;
		else
			right = i - 1;
	}

	return NULL;
}

int
gotd_parseuid(const char *s, uid_t *uid)
{
	struct passwd *pw;
	const char *errstr;

	if ((pw = getpwnam(s)) != NULL) {
		*uid = pw->pw_uid;
		if (*uid == UID_MAX)
			return -1;
		return 0;
	}
	*uid = strtonum(s, 0, UID_MAX - 1, &errstr);
	if (errstr)
		return -1;
	return 0;
}
