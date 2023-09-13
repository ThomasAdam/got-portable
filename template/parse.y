/*
 * Copyright (c) 2022 Omar Polo <op@openbsd.org>
 * Copyright (c) 2007-2016 Reyk Floeter <reyk@openbsd.org>
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

#include <sys/queue.h>

#include <ctype.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#ifndef nitems
#define nitems(_a) (sizeof((_a)) / sizeof((_a)[0]))
#endif

TAILQ_HEAD(files, file)		 files = TAILQ_HEAD_INITIALIZER(files);
static struct file {
	TAILQ_ENTRY(file)	 entry;
	FILE			*stream;
	char			*name;
	size_t			 ungetpos;
	size_t			 ungetsize;
	unsigned char		*ungetbuf;
	int			 eof_reached;
	int			 lineno;
	int			 errors;
} *file, *topfile;
int		 parse(FILE *, const char *);
struct file	*pushfile(const char *, int);
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

void		 dbg(void);
void		 printq(const char *);

extern int	 nodebug;

static FILE	*fp;

static int	 block;
static int	 in_define;
static int	 errors;
static int	 lastline = -1;

typedef struct {
	union {
		char		*string;
	} v;
	int lineno;
} YYSTYPE;

%}

%token	DEFINE ELSE END ERROR FINALLY FOR IF INCLUDE PRINTF
%token	RENDER TQFOREACH UNSAFE URLESCAPE WHILE
%token	<v.string>	STRING
%type	<v.string>	string nstring
%type	<v.string>	stringy

%%

grammar		: /* empty */
		| grammar include
		| grammar verbatim
		| grammar block
		| grammar error		{ file->errors++; }
		;

include		: INCLUDE STRING {
			struct file	*nfile;

			if ((nfile = pushfile($2, 0)) == NULL) {
				yyerror("failed to include file %s", $2);
				free($2);
				YYERROR;
			}
			free($2);

			file = nfile;
			lungetc('\n');
		}
		;

verbatim	: '!' verbatim1 '!' {
			if (in_define) {
				/* TODO: check template status and exit in case */
			}
		}
		;

verbatim1	: /* empty */
		| verbatim1 STRING {
			if (*$2 != '\0') {
				dbg();
				fprintf(fp, "%s\n", $2);
			}
			free($2);
		}
		;

verbatims	: /* empty */
		| verbatims verbatim
		;

raw		: nstring {
			dbg();
			fprintf(fp, "if ((tp_ret = tp_write(tp, ");
			printq($1);
			fprintf(fp, ", %zu)) == -1) goto err;\n",
			    strlen($1));

			free($1);
		}
		;

block		: define body end {
			fputs("err:\n", fp);
			fputs("return tp_ret;\n", fp);
			fputs("}\n", fp);
			in_define = 0;
		}
		| define body finally end {
			fputs("return tp_ret;\n", fp);
			fputs("}\n", fp);
			in_define = 0;
		}
		;

define		: '{' DEFINE string '}' {
			in_define = 1;

			dbg();
			fprintf(fp, "int\n%s\n{\n", $3);
			fputs("int tp_ret = 0;\n", fp);

			free($3);
		}
		;

body		: /* empty */
		| body verbatim
		| body raw
		| body special
		;

special		: '{' RENDER string '}' {
			dbg();
			fprintf(fp, "if ((tp_ret = %s) == -1) goto err;\n",
			    $3);
			free($3);
		}
		| printf
		| if body endif			{ fputs("}\n", fp); }
		| loop
		| '{' string '|' UNSAFE '}' {
			dbg();
			fprintf(fp,
			    "if ((tp_ret = tp_writes(tp, %s)) == -1)\n",
			    $2);
			fputs("goto err;\n", fp);
			free($2);
		}
		| '{' string '|' URLESCAPE '}' {
			dbg();
			fprintf(fp,
			    "if ((tp_ret = tp_urlescape(tp, %s)) == -1)\n",
			    $2);
			fputs("goto err;\n", fp);
			free($2);
		}
		| '{' string '}' {
			dbg();
			fprintf(fp,
			    "if ((tp_ret = tp_htmlescape(tp, %s)) == -1)\n",
			    $2);
			fputs("goto err;\n", fp);
			free($2);
		}
		;

printf		: '{' PRINTF {
			dbg();
			fprintf(fp, "if (asprintf(&tp->tp_tmp, ");
		} printfargs '}' {
			fputs(") == -1)\n", fp);
			fputs("goto err;\n", fp);
			fputs("if ((tp_ret = tp_htmlescape(tp, tp->tp_tmp)) "
			    "== -1)\n", fp);
			fputs("goto err;\n", fp);
			fputs("free(tp->tp_tmp);\n", fp);
			fputs("tp->tp_tmp = NULL;\n", fp);
		}
		;

printfargs	: /* empty */
		| printfargs STRING {
			fprintf(fp, " %s", $2);
			free($2);
		}
		;

if		: '{' IF stringy '}' {
			dbg();
			fprintf(fp, "if (%s) {\n", $3);
			free($3);
		}
		;

endif		: end
		| else body end
		| elsif body endif
		;

elsif		: '{' ELSE IF stringy '}' {
			dbg();
			fprintf(fp, "} else if (%s) {\n", $4);
			free($4);
		}
		;

else		: '{' ELSE '}' {
			dbg();
			fputs("} else {\n", fp);
		}
		;

loop		: '{' FOR stringy '}' {
			fprintf(fp, "for (%s) {\n", $3);
			free($3);
		} body end {
			fputs("}\n", fp);
		}
		| '{' TQFOREACH STRING STRING STRING '}' {
			fprintf(fp, "TAILQ_FOREACH(%s, %s, %s) {\n",
			    $3, $4, $5);
			free($3);
			free($4);
			free($5);
		} body end {
			fputs("}\n", fp);
		}
		| '{' WHILE stringy '}' {
			fprintf(fp, "while (%s) {\n", $3);
			free($3);
		} body end {
			fputs("}\n", fp);
		}
		;

end		: '{' END '}'
		;

finally		: '{' FINALLY '}' {
			dbg();
			fputs("err:\n", fp);
		} verbatims
		;

nstring	:	STRING nstring {
			if (asprintf(&$$, "%s%s", $1, $2) == -1)
				err(1, "asprintf");
			free($1);
			free($2);
		}
		| STRING
		;

string		: STRING string {
			if (asprintf(&$$, "%s %s", $1, $2) == -1)
				err(1, "asprintf");
			free($1);
			free($2);
		}
		| STRING
		;

stringy		: STRING
		| STRING stringy {
			if (asprintf(&$$, "%s %s", $1, $2) == -1)
				err(1, "asprintf");
			free($1);
			free($2);
		}
		| '|' stringy {
			if (asprintf(&$$, "|%s", $2) == -1)
				err(1, "asprintf");
			free($2);
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
	va_list	 ap;
	char	*msg;

	file->errors++;
	va_start(ap, fmt);
	if (vasprintf(&msg, fmt, ap) == -1)
		err(1, "yyerror vasprintf");
	va_end(ap);
	fprintf(stderr, "%s:%d: %s\n", file->name, yylval.lineno, msg);
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
		{ "define",		DEFINE },
		{ "else",		ELSE },
		{ "end",		END },
		{ "finally",		FINALLY },
		{ "for",		FOR },
		{ "if",			IF },
		{ "include",		INCLUDE },
		{ "printf",		PRINTF },
		{ "render",		RENDER },
		{ "tailq-foreach",	TQFOREACH },
		{ "unsafe",		UNSAFE },
		{ "urlescape",		URLESCAPE },
		{ "while",		WHILE },
	};
	const struct keywords	*p;

	p = bsearch(s, keywords, nitems(keywords), sizeof(keywords[0]),
	    kw_cmp);

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
	int		c;

	if (quotec) {
		if ((c = igetc()) == EOF) {
			yyerror("reached end of filewhile parsing "
			    "quoted string");
			if (file == topfile || popfile() == EOF)
				return (EOF);
			return (quotec);
		}
		return (c);
	}

	c = igetc();
	if (c == '\t' || c == ' ') {
		/* Compress blanks to a sigle space. */
		do {
			c = getc(file->stream);
		} while (c == '\t'  || c == ' ');
		ungetc(c, file->stream);
		c = ' ';
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
			err(1, "reallocarray");
		file->ungetbuf = p;
		file->ungetsize *= 2;
	}
	file->ungetbuf[file->ungetpos++] = c;
}

int
findeol(void)
{
	int	c;

	/* skip to either EOF or the first real EOL */
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
	char		 buf[8096];
	char		*p = buf;
	int		 c;
	int		 token;
	int		 starting = 0;
	int		 ending = 0;
	int		 quote = 0;

	if (!in_define && block == 0) {
		while ((c = lgetc(0)) != '{' && c != EOF) {
			if (c == '\n')
				file->lineno++;
		}

		if (c == EOF)
			return (0);

newblock:
		c = lgetc(0);
		if (c == '{' || c == '!') {
			if (c == '{')
				block = '}';
			else
				block = c;
			return (c);
		}
		if (c == '\n')
			file->lineno++;
	}

	while ((c = lgetc(0)) == ' ' || c == '\t' || c == '\n') {
		if (c == '\n')
			file->lineno++;
	}

	if (c == EOF) {
		yyerror("unterminated block");
		return (0);
	}

	yylval.lineno = file->lineno;

	if (block != 0 && c == block) {
		if ((c = lgetc(0)) == '}') {
			if (block == '!') {
				block = 0;
				return ('!');
			}
			block = 0;
			return ('}');
		}
		lungetc(c);
		c = block;
	}

	if (in_define && block == 0) {
		if (c == '{')
			goto newblock;

		do {
			if (starting) {
				if (c == '!' || c == '{') {
					lungetc(c);
					lungetc('{');
					break;
				}
				starting = 0;
				lungetc(c);
				c = '{';
			} else if (c == '{') {
				starting = 1;
				continue;
			} else if (c == '\n')
				break;

			*p++ = c;
			if ((size_t)(p - buf) >= sizeof(buf)) {
				yyerror("string too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF);
		*p = '\0';
		if (c == EOF) {
			yyerror("unterminated block");
			return (0);
		}
		if (c == '\n')
			file->lineno++;
		if ((yylval.v.string = strdup(buf)) == NULL)
			err(1, "strdup");
		return (STRING);
	}

	if (block == '!') {
		do {
			if (ending) {
				if (c == '}') {
					lungetc(c);
					lungetc(block);
					break;
				}
				ending = 0;
				lungetc(c);
				c = block;
			} else if (c == '!') {
				ending = 1;
				continue;
			} else if (c == '\n')
				break;

			*p++ = c;
			if ((size_t)(p - buf) >= sizeof(buf)) {
				yyerror("line too long");
				return (findeol());
			}
		} while ((c = lgetc(0)) != EOF);
		*p = '\0';

		if (c == EOF) {
			yyerror("unterminated block");
			return (0);
		}
		if (c == '\n')
			file->lineno++;

		if ((yylval.v.string = strdup(buf)) == NULL)
			err(1, "strdup");
		return (STRING);
	}

	if (c == '|')
		return (c);

	do {
		if (!quote && isspace((unsigned char)c))
			break;

		if (c == '"')
			quote = !quote;

		if (!quote && c == '|') {
			lungetc(c);
			break;
		}

		if (ending) {
			if (c == '}') {
				lungetc(c);
				lungetc('}');
				break;
			}
			ending = 0;
			lungetc(c);
			c = block;
		} else if (!quote && c == '}') {
			ending = 1;
			continue;
		}

		*p++ = c;
		if ((size_t)(p - buf) >= sizeof(buf)) {
			yyerror("string too long");
			return (findeol());
		}
	} while ((c = lgetc(0)) != EOF);
	*p = '\0';

	if (c == EOF) {
		yyerror(quote ? "unterminated quote" : "unterminated block");
		return (0);
	}
	if (c ==  '\n')
		file->lineno++;
	if ((token = lookup(buf)) == STRING)
		if ((yylval.v.string = strdup(buf)) == NULL)
			err(1, "strdup");
	return (token);
}

struct file *
pushfile(const char *name, int secret)
{
	struct file	*nfile;

	if ((nfile = calloc(1, sizeof(*nfile))) == NULL)
		err(1, "calloc");
	if ((nfile->name = strdup(name)) == NULL)
		err(1, "strdup");
	if ((nfile->stream = fopen(nfile->name, "r")) == NULL) {
		warn("can't open %s", nfile->name);
		free(nfile->name);
		free(nfile);
		return (NULL);
	}
	nfile->lineno = TAILQ_EMPTY(&files) ? 1 : 0;
	nfile->ungetsize = 16;
	nfile->ungetbuf = malloc(nfile->ungetsize);
	if (nfile->ungetbuf == NULL)
		err(1, "malloc");
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
	free(file->ungetbuf);
	free(file);
	file = prev;
	return (file ? 0 : EOF);
}

int
parse(FILE *outfile, const char *filename)
{
	fp = outfile;

	if ((file = pushfile(filename, 0)) == 0)
		return (-1);
	topfile = file;

	yyparse();
	errors = file->errors;
	popfile();

	return (errors ? -1 : 0);
}

void
dbg(void)
{
	if (nodebug)
		return;

	if (yylval.lineno == lastline + 1) {
		lastline = yylval.lineno;
		return;
	}
	lastline = yylval.lineno;

	fprintf(fp, "#line %d ", yylval.lineno);
	printq(file->name);
	putc('\n', fp);
}

void
printq(const char *str)
{
	putc('"', fp);
	for (; *str; ++str) {
		if (*str == '"')
			putc('\\', fp);
		putc(*str, fp);
	}
	putc('"', fp);
}
