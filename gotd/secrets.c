/*
 * Copyright (c) 2024 Omar Polo <op@openbsd.org>
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

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "got_error.h"

#include "log.h"
#include "secrets.h"

static const struct got_error *
push(struct gotd_secrets *s, enum gotd_secret_type type, const char *label,
    const char *user, const char *pass, const char *hmac)
{
	size_t			 newcap, i;
	void			*t;

	if (s->len == s->cap) {
		newcap = s->cap + 16;
		t = reallocarray(s->secrets, newcap, sizeof(*s->secrets));
		if (t == NULL)
			return got_error_from_errno("reallocarray");
		s->secrets = t;
		s->cap = newcap;
	}

	i = s->len;
	memset(&s->secrets[i], 0, sizeof(s->secrets[i]));
	s->secrets[i].type = type;
	s->secrets[i].label = strdup(label);
	if (s->secrets[i].label == NULL)
		return got_error_from_errno("strdup");

	if (type == GOTD_SECRET_AUTH) {
		s->secrets[i].user = strdup(user);
		if (s->secrets[i].user == NULL)
			return got_error_from_errno("strdup");
		s->secrets[i].pass = strdup(pass);
		if (s->secrets[i].pass == NULL)
			return got_error_from_errno("strdup");
	} else {
		s->secrets[i].hmac = strdup(hmac);
		if (s->secrets[i].hmac == NULL)
			return got_error_from_errno("strdup");
	}

	s->len++;
	return NULL;
}

static char *
read_word(char **word, const char *path, int lineno, char *s)
{
	char			*p, quote = 0;
	int			 escape = 0;

	s += strspn(s, " \t");
	if (*s == '\0') {
		log_warnx("%s:%d syntax error", path, lineno);
		return NULL;
	}
	*word = s;

	p = s;
	while (*s) {
		if (escape) {
			escape = 0;
			*p++ = *s++;
			continue;
		}

		if (*s == '\\') {
			escape = 1;
			s++;
			continue;
		}

		if (*s == quote) {
			quote = 0;
			s++;
			continue;
		}

		if (*s == '\'' || *s == '\"') {
			quote = *s;
			s++;
			continue;
		}

		if (!quote && (*s == ' ' || *s == '\t')) {
			*p = '\0';
			return s + 1;
		}

		*p++ = *s++;
	}

	if (quote) {
		log_warnx("%s:%d no closing quote", path, lineno);
		return NULL;
	}

	if (escape) {
		log_warnx("%s:%d unterminated escape at end of line",
		    path, lineno);
		return NULL;
	}

	*p = '\0';
	return s;
}

static char *
read_keyword(char **kw, const char *path, int lineno, char *s)
{
	s += strspn(s, " \t");
	if (*s == '\0') {
		log_warnx("%s:%d syntax error", path, lineno);
		return NULL;
	}
	*kw = s;

	s += strcspn(s, " \t");
	if (*s != '\0')
		*s++ = '\0';
	return s;
}

static const struct got_error *
parse_line(struct gotd_secrets *secrets, const char *path, int lineno,
    char *line)
{
	char			*kw, *label;
	char			*user = NULL, *pass = NULL, *hmac = NULL;
	enum gotd_secret_type	 type;

	line = read_keyword(&kw, path, lineno, line);
	if (line == NULL)
		return got_error(GOT_ERR_PARSE_CONFIG);

	if (!strcmp(kw, "auth"))
		type = GOTD_SECRET_AUTH;
	else if (!strcmp(kw, "hmac"))
		type = GOTD_SECRET_HMAC;
	else {
		log_warnx("%s:%d syntax error", path, lineno);
		return got_error(GOT_ERR_PARSE_CONFIG);
	}

	line = read_word(&label, path, lineno, line);
	if (line == NULL)
		return got_error(GOT_ERR_PARSE_CONFIG);

	if (type == GOTD_SECRET_AUTH) {
		line = read_keyword(&kw, path, lineno, line);
		if (line == NULL)
			return got_error(GOT_ERR_PARSE_CONFIG);
		if (strcmp(kw, "user") != 0) {
			log_warnx("%s:%d syntax error", path, lineno);
			return got_error(GOT_ERR_PARSE_CONFIG);
		}

		line = read_word(&user, path, lineno, line);
		if (line == NULL)
			return got_error(GOT_ERR_PARSE_CONFIG);

		line = read_keyword(&kw, path, lineno, line);
		if (line == NULL)
			return got_error(GOT_ERR_PARSE_CONFIG);
		if (strcmp(kw, "password") != 0) {
			log_warnx("%s:%d syntax error", path, lineno);
			return got_error(GOT_ERR_PARSE_CONFIG);
		}

		line = read_word(&pass, path, lineno, line);
		if (line == NULL)
			return got_error(GOT_ERR_PARSE_CONFIG);
	} else {
		line = read_word(&hmac, path, lineno, line);
		if (line == NULL)
			return got_error(GOT_ERR_PARSE_CONFIG);
	}

	line += strspn(line, " \t");
	if (*line != '\0') {
		log_warnx("%s:%d syntax error", path, lineno);
		return got_error(GOT_ERR_PARSE_CONFIG);
	}

	if (gotd_secrets_get(secrets, type, label) != NULL) {
		log_warnx("%s:%d duplicate %s entry %s", path, lineno,
		    type == GOTD_SECRET_AUTH ? "auth" : "hmac", label);
		return got_error(GOT_ERR_PARSE_CONFIG);
	}

	return push(secrets, type, label, user, pass, hmac);
}

const struct got_error *
gotd_secrets_parse(const char *path, FILE *fp, struct gotd_secrets **s)
{
	const struct got_error	*err = NULL;
	int			 lineno = 0;
	char			*line = NULL;
	size_t			 linesize = 0;
	ssize_t			 linelen;
	char			*t;
	struct gotd_secrets	*secrets;

	*s = NULL;

	secrets = calloc(1, sizeof(*secrets));
	if (secrets == NULL)
		return got_error_from_errno("calloc");

	while ((linelen = getline(&line, &linesize, fp)) != -1) {
		lineno++;
		if (line[linelen - 1] == '\n')
			line[--linelen] = '\0';

		for (t = line; *t == ' ' || *t == '\t'; ++t)
			/* nop */ ;

		if (*t == '\0' || *t == '#')
			continue;

		err = parse_line(secrets, path, lineno, t);
		if (err)
			break;
	}
	free(line);
	if (ferror(fp) && err == NULL)
		err = got_error_from_errno("getline");

	if (err) {
		gotd_secrets_free(secrets);
		secrets = NULL;
	}

	*s = secrets;
	return err;
}

struct gotd_secret *
gotd_secrets_get(struct gotd_secrets *s, enum gotd_secret_type type,
    const char *label)
{
	size_t		 i;

	for (i = 0; i < s->len; ++i) {
		if (s->secrets[i].type != type)
			continue;
		if (strcmp(s->secrets[i].label, label) != 0)
			continue;
		return &s->secrets[i];
	}

	return NULL;
}

void
gotd_secrets_free(struct gotd_secrets *s)
{
	size_t		 i;

	if (s == NULL)
		return;

	for (i = 0; i < s->len; ++i) {
		free(s->secrets[i].label);
		free(s->secrets[i].user);
		free(s->secrets[i].pass);
		free(s->secrets[i].hmac);
	}

	free(s);
}
