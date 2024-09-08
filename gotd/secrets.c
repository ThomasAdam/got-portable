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
push(struct gotd_secrets *s, const char *path, int lineno,
    const char *type, const char *key, const char *val)
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
	if (!strcmp(type, "auth"))
		s->secrets[i].type = GOTD_SECRET_AUTH;
	else if (!strcmp(type, "hmac"))
		s->secrets[i].type = GOTD_SECRET_HMAC;
	else {
		log_warnx("%s:%d invalid type %s", path, lineno, type);
		return got_error(GOT_ERR_PARSE_CONFIG);
	}

	if (gotd_secrets_get(s, s->secrets[i].type, key) != NULL) {
		log_warnx("%s:%d duplicate %s entry %s", path, lineno,
		    type, key);
		return got_error(GOT_ERR_PARSE_CONFIG);
	}

	s->secrets[i].key = strdup(key);
	if (s->secrets[i].key == NULL)
		return got_error_from_errno("strdup");
	s->secrets[i].val = strdup(val);
	if (s->secrets[i].val == NULL)
		return got_error_from_errno("strdup");

	s->len++;
	return NULL;
}

const struct got_error *
gotd_secrets_parse(const char *path, FILE *fp, struct gotd_secrets **s)
{
	const struct got_error	*err = NULL;
	int			 lineno = 0;
	char			*line = NULL;
	size_t			 linesize = 0;
	ssize_t			 linelen;
	char			*type, *key, *val, *t;
	struct gotd_secrets	*secrets;

	*s = NULL;

	secrets = calloc(1, sizeof(*secrets));
	if (secrets == NULL)
		return got_error_from_errno("calloc");

	while ((linelen = getline(&line, &linesize, fp)) != -1) {
		lineno++;
		if (line[linelen - 1] == '\n')
			line[--linelen] = '\0';

		if (*line == '\0' || *line == '#')
			continue;

		type = line;

		key = type + strcspn(type, " \t");
		*key++ = '\0';
		key += strspn(key, " \t");

		val = key + strcspn(key, " \t");
		*val++ = '\0';
		val += strspn(val, " \t");

		t = val + strcspn(val, " \t");
		if (*t != '\0') {
			log_warnx("%s:%d malformed entry\n", path, lineno);
			err = got_error(GOT_ERR_PARSE_CONFIG);
			break;
		}

		err = push(secrets, path, lineno, type, key, val);
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

const char *
gotd_secrets_get(struct gotd_secrets *s, enum gotd_secret_type type,
    const char *key)
{
	size_t		 i;

	for (i = 0; i < s->len; ++i) {
		if (s->secrets[i].type != type)
			continue;
		if (strcmp(s->secrets[i].key, key) != 0)
			continue;
		return s->secrets[i].val;
	}

	return NULL;
}

void
gotd_secrets_free(struct gotd_secrets *s)
{
	size_t		 i;

	for (i = 0; i < s->len; ++i) {
		free(s->secrets[i].key);
		free(s->secrets[i].val);
	}

	free(s);
}
