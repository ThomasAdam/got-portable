/*
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
#include "got_compat.h"

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <net/if.h>
#include <netinet/in.h>

#include <arpa/inet.h>

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <event.h>
#include <ifaddrs.h>
#include <limits.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "got_sockaddr.h"
#include "got_reference.h"

#include "proc.h"
#include "gotwebd.h"

TAILQ_HEAD(files, file)		 files = TAILQ_HEAD_INITIALIZER(files);
static struct file {
	TAILQ_ENTRY(file)	 entry;
	FILE			*stream;
	char			*name;
	int			 lineno;
	int			 errors;
} *file;
struct file	*newfile(const char *, int);
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

static struct gotwebd		*gotwebd;
static struct server		*new_srv;
static struct server		*conf_new_server(const char *);
int				 getservice(const char *);
int				 n;

int		 get_addrs(const char *, const char *, struct server *);
int		 addr_dup_check(struct addresslist *, struct address *,
		    const char *, const char *);
int		 add_addr(struct server *, struct address *);

typedef struct {
	union {
		long long	 number;
		char		*string;
	} v;
	int lineno;
} YYSTYPE;

%}

%token	LISTEN WWW_PATH MAX_REPOS SITE_NAME SITE_OWNER SITE_LINK LOGO
%token	LOGO_URL SHOW_REPO_OWNER SHOW_REPO_AGE SHOW_REPO_DESCRIPTION
%token	MAX_REPOS_DISPLAY REPOS_PATH MAX_COMMITS_DISPLAY ON ERROR
%token	SHOW_SITE_OWNER SHOW_REPO_CLONEURL PORT PREFORK RESPECT_EXPORTOK
%token	UNIX_SOCKET UNIX_SOCKET_NAME SERVER CHROOT CUSTOM_CSS SOCKET

%token	<v.string>	STRING
%token	<v.number>	NUMBER
%type	<v.number>	boolean
%type	<v.string>	listen_addr

%%

grammar		: /* empty */
		| grammar '\n'
		| grammar varset '\n'
		| grammar main '\n'
		| grammar server '\n'
		| grammar error '\n'		{ file->errors++; }
		;

varset		: STRING '=' STRING	{
			char *s = $1;
			while (*s++) {
				if (isspace((unsigned char)*s)) {
					yyerror("macro name cannot contain "
					    "whitespace");
					free($1);
					free($3);
					YYERROR;
				}
			}
			if (symset($1, $3, 0) == -1)
				fatal("cannot store variable");
			free($1);
			free($3);
		}
		;

boolean		: STRING {
			if (strcasecmp($1, "1") == 0 ||
			    strcasecmp($1, "on") == 0)
				$$ = 1;
			else if (strcasecmp($1, "0") == 0 ||
			    strcasecmp($1, "off") == 0)
				$$ = 0;
			else {
				yyerror("invalid boolean value '%s'", $1);
				free($1);
				YYERROR;
			}
			free($1);
		}
		| ON { $$ = 1; }
		| NUMBER {
			if ($1 != 0 && $1 != 1) {
				yyerror("invalid boolean value '%lld'", $1);
				YYERROR;
			}
			$$ = $1;
		}
		;

listen_addr	: '*' { $$ = NULL; }
		| STRING
		;

main		: PREFORK NUMBER {
			if ($2 <= 0 || $2 > PROC_MAX_INSTANCES) {
				yyerror("prefork is %s: %lld",
				    $2 <= 0 ? "too small" : "too large", $2);
				YYERROR;
			}
			gotwebd->prefork_gotwebd = $2;
		}
		| CHROOT STRING {
			if (*$2 == '\0') {
				yyerror("chroot path can't be an empty"
				    " string");
				free($2);
				YYERROR;
			}

			n = strlcpy(gotwebd->httpd_chroot, $2,
			    sizeof(gotwebd->httpd_chroot));
			if (n >= sizeof(gotwebd->httpd_chroot)) {
				yyerror("%s: httpd_chroot truncated", __func__);
				free($2);
				YYERROR;
			}
			free($2);
		}
		| UNIX_SOCKET boolean {
			gotwebd->unix_socket = $2;
		}
		| UNIX_SOCKET_NAME STRING {
			n = snprintf(gotwebd->unix_socket_name,
			    sizeof(gotwebd->unix_socket_name), "%s%s",
			    gotwebd->httpd_chroot, $2);
			if (n < 0 ||
			    (size_t)n >= sizeof(gotwebd->unix_socket_name)) {
				yyerror("%s: unix_socket_name truncated",
				    __func__);
				free($2);
				YYERROR;
			}
			free($2);
		}
		;

server		: SERVER STRING {
			struct server *srv;

			TAILQ_FOREACH(srv, &gotwebd->servers, entry) {
				if (strcmp(srv->name, $2) == 0) {
					yyerror("server name exists '%s'", $2);
					free($2);
					YYERROR;
				}
			}

			new_srv = conf_new_server($2);
			log_debug("adding server %s", $2);
			free($2);
		}
		| SERVER STRING {
			struct server *srv;

			TAILQ_FOREACH(srv, &gotwebd->servers, entry) {
				if (strcmp(srv->name, $2) == 0) {
					yyerror("server name exists '%s'", $2);
					free($2);
					YYERROR;
				}
			}

			new_srv = conf_new_server($2);
			log_debug("adding server %s", $2);
			free($2);
		} '{' optnl serveropts2 '}' {
		}
		;

serveropts1	: REPOS_PATH STRING {
			n = strlcpy(new_srv->repos_path, $2,
			    sizeof(new_srv->repos_path));
			if (n >= sizeof(new_srv->repos_path)) {
				yyerror("%s: repos_path truncated", __func__);
				free($2);
				YYERROR;
			}
			free($2);
		}
		| SITE_NAME STRING {
			n = strlcpy(new_srv->site_name, $2,
			    sizeof(new_srv->site_name));
			if (n >= sizeof(new_srv->site_name)) {
				yyerror("%s: site_name truncated", __func__);
				free($2);
				YYERROR;
			}
			free($2);
		}
		| SITE_OWNER STRING {
			n = strlcpy(new_srv->site_owner, $2,
			    sizeof(new_srv->site_owner));
			if (n >= sizeof(new_srv->site_owner)) {
				yyerror("%s: site_owner truncated", __func__);
				free($2);
				YYERROR;
			}
			free($2);
		}
		| SITE_LINK STRING {
			n = strlcpy(new_srv->site_link, $2,
			    sizeof(new_srv->site_link));
			if (n >= sizeof(new_srv->site_link)) {
				yyerror("%s: site_link truncated", __func__);
				free($2);
				YYERROR;
			}
			free($2);
		}
		| LOGO STRING {
			n = strlcpy(new_srv->logo, $2, sizeof(new_srv->logo));
			if (n >= sizeof(new_srv->logo)) {
				yyerror("%s: logo truncated", __func__);
				free($2);
				YYERROR;
			}
			free($2);
		}
		| LOGO_URL STRING {
			n = strlcpy(new_srv->logo_url, $2,
			    sizeof(new_srv->logo_url));
			if (n >= sizeof(new_srv->logo_url)) {
				yyerror("%s: logo_url truncated", __func__);
				free($2);
				YYERROR;
			}
			free($2);
		}
		| CUSTOM_CSS STRING {
			n = strlcpy(new_srv->custom_css, $2,
			    sizeof(new_srv->custom_css));
			if (n >= sizeof(new_srv->custom_css)) {
				yyerror("%s: custom_css truncated", __func__);
				free($2);
				YYERROR;
			}
			free($2);
		}
		| LISTEN ON listen_addr PORT STRING {
			if (get_addrs($3, $5, new_srv) == -1) {
				yyerror("could not get addrs");
				YYERROR;
			}
			free($3);
			free($5);
			new_srv->fcgi_socket = 1;
		}
		| LISTEN ON listen_addr PORT NUMBER {
			char portno[32];
			int n;

			n = snprintf(portno, sizeof(portno), "%lld",
			    (long long)$5);
			if (n < 0 || (size_t)n >= sizeof(portno))
				fatalx("port number too long: %lld",
				    (long long)$5);

			if (get_addrs($3, portno, new_srv) == -1) {
				yyerror("could not get addrs");
				YYERROR;
			}
			free($3);
			new_srv->fcgi_socket = 1;
		}
		| LISTEN ON SOCKET STRING {
			if (strcasecmp($4, "off") == 0) {
				new_srv->unix_socket = 0;
				free($4);
				YYACCEPT;
			}

			new_srv->unix_socket = 1;

			n = snprintf(new_srv->unix_socket_name,
			    sizeof(new_srv->unix_socket_name), "%s%s",
			    gotwebd->httpd_chroot, $4);
			if (n < 0 ||
			    (size_t)n >= sizeof(new_srv->unix_socket_name)) {
				yyerror("%s: unix_socket_name truncated",
				    __func__);
				free($4);
				YYERROR;
			}
			free($4);
		}
		| MAX_REPOS NUMBER {
			if ($2 <= 0) {
				yyerror("max_repos is too small: %lld", $2);
				YYERROR;
			}
			new_srv->max_repos = $2;
		}
		| SHOW_SITE_OWNER boolean {
			new_srv->show_site_owner = $2;
		}
		| SHOW_REPO_OWNER boolean {
			new_srv->show_repo_owner = $2;
		}
		| SHOW_REPO_AGE boolean {
			new_srv->show_repo_age = $2;
		}
		| SHOW_REPO_DESCRIPTION boolean {
			new_srv->show_repo_description = $2;
		}
		| SHOW_REPO_CLONEURL boolean {
			new_srv->show_repo_cloneurl = $2;
		}
		| RESPECT_EXPORTOK boolean {
			new_srv->respect_exportok = $2;
		}
		| MAX_REPOS_DISPLAY NUMBER {
			if ($2 < 0) {
				yyerror("max_repos_display is too small: %lld",
				    $2);
				YYERROR;
			}
			new_srv->max_repos_display = $2;
		}
		| MAX_COMMITS_DISPLAY NUMBER {
			if ($2 <= 1) {
				yyerror("max_commits_display is too small:"
				    " %lld", $2);
				YYERROR;
			}
			new_srv->max_commits_display = $2;
		}
		;

serveropts2	: serveropts2 serveropts1 nl
		| serveropts1 optnl
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
		{ "chroot",			CHROOT },
		{ "custom_css",			CUSTOM_CSS },
		{ "listen",			LISTEN },
		{ "logo",			LOGO },
		{ "logo_url",			LOGO_URL },
		{ "max_commits_display",	MAX_COMMITS_DISPLAY },
		{ "max_repos",			MAX_REPOS },
		{ "max_repos_display",		MAX_REPOS_DISPLAY },
		{ "on",				ON },
		{ "port",			PORT },
		{ "prefork",			PREFORK },
		{ "repos_path",			REPOS_PATH },
		{ "respect_exportok",		RESPECT_EXPORTOK },
		{ "server",			SERVER },
		{ "show_repo_age",		SHOW_REPO_AGE },
		{ "show_repo_cloneurl",		SHOW_REPO_CLONEURL },
		{ "show_repo_description",	SHOW_REPO_DESCRIPTION },
		{ "show_repo_owner",		SHOW_REPO_OWNER },
		{ "show_site_owner",		SHOW_SITE_OWNER },
		{ "site_link",			SITE_LINK },
		{ "site_name",			SITE_NAME },
		{ "site_owner",			SITE_OWNER },
		{ "socket",			SOCKET },
		{ "unix_socket",		UNIX_SOCKET },
		{ "unix_socket_name",		UNIX_SOCKET_NAME },
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
newfile(const char *name, int secret)
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
		/* no warning, we don't require a conf file */
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

static void
add_default_server(void)
{
	new_srv = conf_new_server(D_SITENAME);
	log_debug("%s: adding default server %s", __func__, D_SITENAME);
}

int
parse_config(const char *filename, struct gotwebd *env)
{
	struct sym *sym, *next;

	if (config_init(env) == -1)
		fatalx("failed to initialize configuration");

	gotwebd = env;

	file = newfile(filename, 0);
	if (file == NULL) {
		add_default_server();
		sockets_parse_sockets(env);
		/* just return, as we don't require a conf file */
		return (0);
	}

	yyparse();
	errors = file->errors;
	closefile(file);

	/* Free macros and check which have not been used. */
	TAILQ_FOREACH_SAFE(sym, &symhead, entry, next) {
		if ((gotwebd->gotwebd_verbose > 1) && !sym->used)
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

	/* just add default server if no config specified */
	if (gotwebd->server_cnt == 0)
		add_default_server();

	/* setup our listening sockets */
	sockets_parse_sockets(env);

	return (0);
}

struct server *
conf_new_server(const char *name)
{
	struct server *srv = NULL;

	srv = calloc(1, sizeof(*srv));
	if (srv == NULL)
		fatalx("%s: calloc", __func__);

	n = strlcpy(srv->name, name, sizeof(srv->name));
	if (n >= sizeof(srv->name))
		fatalx("%s: strlcpy", __func__);
	n = snprintf(srv->unix_socket_name,
	    sizeof(srv->unix_socket_name), "%s%s", D_HTTPD_CHROOT,
	    D_UNIX_SOCKET);
	if (n < 0 || (size_t)n >= sizeof(srv->unix_socket_name))
		fatalx("%s: snprintf", __func__);
	n = strlcpy(srv->repos_path, D_GOTPATH,
	    sizeof(srv->repos_path));
	if (n >= sizeof(srv->repos_path))
		fatalx("%s: strlcpy", __func__);
	n = strlcpy(srv->site_name, D_SITENAME,
	    sizeof(srv->site_name));
	if (n >= sizeof(srv->site_name))
		fatalx("%s: strlcpy", __func__);
	n = strlcpy(srv->site_owner, D_SITEOWNER,
	    sizeof(srv->site_owner));
	if (n >= sizeof(srv->site_owner))
		fatalx("%s: strlcpy", __func__);
	n = strlcpy(srv->site_link, D_SITELINK,
	    sizeof(srv->site_link));
	if (n >= sizeof(srv->site_link))
		fatalx("%s: strlcpy", __func__);
	n = strlcpy(srv->logo, D_GOTLOGO,
	    sizeof(srv->logo));
	if (n >= sizeof(srv->logo))
		fatalx("%s: strlcpy", __func__);
	n = strlcpy(srv->logo_url, D_GOTURL, sizeof(srv->logo_url));
	if (n >= sizeof(srv->logo_url))
		fatalx("%s: strlcpy", __func__);
	n = strlcpy(srv->custom_css, D_GOTWEBCSS, sizeof(srv->custom_css));
	if (n >= sizeof(srv->custom_css))
		fatalx("%s: strlcpy", __func__);

	srv->show_site_owner = D_SHOWSOWNER;
	srv->show_repo_owner = D_SHOWROWNER;
	srv->show_repo_age = D_SHOWAGE;
	srv->show_repo_description = D_SHOWDESC;
	srv->show_repo_cloneurl = D_SHOWURL;
	srv->respect_exportok = D_RESPECTEXPORTOK;

	srv->max_repos_display = D_MAXREPODISP;
	srv->max_commits_display = D_MAXCOMMITDISP;
	srv->max_repos = D_MAXREPO;

	srv->unix_socket = 1;
	srv->fcgi_socket = 0;

	TAILQ_INIT(&srv->al);
	TAILQ_INSERT_TAIL(&gotwebd->servers, srv, entry);
	gotwebd->server_cnt++;

	return srv;
};

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

int
cmdline_symset(char *s)
{
	char *sym, *val;
	int ret;

	val = strrchr(s, '=');
	if (val == NULL)
		return (-1);

	sym = strndup(s, val - s);
	if (sym == NULL)
		fatal("%s: strndup", __func__);

	ret = symset(sym, val + 1, 1);
	free(sym);

	return (ret);
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

int
get_addrs(const char *hostname, const char *servname, struct server *new_srv)
{
	struct addrinfo hints, *res0, *res;
	int error;
	struct sockaddr_in *sain, *ra;
	struct sockaddr_in6 *sin6, *ra6;
	struct address *h;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
	error = getaddrinfo(hostname, servname, &hints, &res0);
	if (error) {
		log_warnx("%s: could not parse \"%s:%s\": %s", __func__,
		    hostname, servname, gai_strerror(error));
		return (-1);
	}

	for (res = res0; res; res = res->ai_next) {
		if ((h = calloc(1, sizeof(*h))) == NULL)
			fatal(__func__);

		if (hostname == NULL) {
			strlcpy(h->ifname, "*", sizeof(h->ifname));
		} else {
			if (strlcpy(h->ifname, hostname, sizeof(h->ifname)) >=
			    sizeof(h->ifname)) {
				log_warnx("%s: address truncated: %s",
				    __func__, hostname);
				freeaddrinfo(res0);
				free(h);
				return (-1);
			}
		}
		h->ss.ss_family = res->ai_family;

		switch (res->ai_family) {
		case AF_INET:
			sain = (struct sockaddr_in *)&h->ss;
			ra = (struct sockaddr_in *)res->ai_addr;
			h->port = ntohs(ra->sin_port);
			got_sockaddr_inet_init(sain, &ra->sin_addr);
			break;
		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)&h->ss;
			ra6 = (struct sockaddr_in6 *)res->ai_addr;
			h->port = ntohs(ra6->sin6_port);
			got_sockaddr_inet6_init(sin6, &ra6->sin6_addr, 0);
			break;
		default:
			fatalx("unknown address family %d", res->ai_family);
		}

		if (add_addr(new_srv, h))
			return -1;
	}
	freeaddrinfo(res0);
	return (0);
}

int
addr_dup_check(struct addresslist *al, struct address *h, const char *new_srv,
    const char *other_srv)
{
	struct address *a;
	void *ia;
	char buf[INET6_ADDRSTRLEN];
	const char *addrstr;

	TAILQ_FOREACH(a, al, entry) {
		if (memcmp(&a->ss, &h->ss, sizeof(h->ss)) != 0 ||
		    a->port != h->port)
			continue;

		switch (h->ss.ss_family) {
		case AF_INET:
			ia = &((struct sockaddr_in *)(&h->ss))->sin_addr;
			break;
		case AF_INET6:
			ia = &((struct sockaddr_in6 *)(&h->ss))->sin6_addr;
			break;
		default:
			yyerror("unknown address family: %d", h->ss.ss_family);
			return -1;
		}
		addrstr = inet_ntop(h->ss.ss_family, ia, buf, sizeof(buf));
		if (addrstr) {
			if (other_srv) {
				yyerror("server %s: duplicate fcgi listen "
				    "address %s:%d, already used by server %s",
				    new_srv, addrstr, h->port, other_srv);
			} else {
				log_warnx("server: %s: duplicate fcgi listen "
				    "address %s:%d", new_srv, addrstr, h->port);
			}
		} else {
			if (other_srv) {
				yyerror("server: %s: duplicate fcgi listen "
				    "address, already used by server %s",
				    new_srv, other_srv);
			} else {
				log_warnx("server %s: duplicate fcgi listen "
				    "address", new_srv);
			}
		}

		return -1;
	}

	return 0;
}

int
add_addr(struct server *new_srv, struct address *h)
{
	struct server *srv;

	/* Address cannot be shared between different servers. */
	TAILQ_FOREACH(srv, &gotwebd->servers, entry) {
		if (srv == new_srv)
			continue;
		if (addr_dup_check(&srv->al, h, new_srv->name, srv->name))
			return -1;
	}

	/* Tolerate duplicate address lines within the scope of a server. */
	if (addr_dup_check(&new_srv->al, h, NULL, NULL) == 0)
		TAILQ_INSERT_TAIL(&new_srv->al, h, entry);
	else
		free(h);

	return 0;
}
