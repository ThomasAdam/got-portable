/*
 * Copyright (c) 2019 Ori Bernstein <ori@openbsd.org>
 * Copyright (c) 2021 Stefan Sperling <stsp@openbsd.org>
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

#include <sys/queue.h>
#include <sys/types.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "got_error.h"
#include "got_path.h"

#include "got_lib_gitproto.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

static const struct got_error *
tokenize_refline(char **tokens, char *line, int len, int maxtokens)
{
	const struct got_error *err = NULL;
	char *p;
	size_t i, n = 0;

	for (i = 0; i < maxtokens; i++)
		tokens[i] = NULL;

	for (i = 0; n < len && i < maxtokens; i++) {
		while (isspace(*line)) {
			line++;
			n++;
		}
		p = line;
		while (*line != '\0' && n < len &&
		    (!isspace(*line) || i == maxtokens - 1)) {
			line++;
			n++;
		}
		tokens[i] = strndup(p, line - p);
		if (tokens[i] == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		/* Skip \0 field-delimiter at end of token. */
		while (line[0] == '\0' && n < len) {
			line++;
			n++;
		}
	}
	if (i <= 2)
		err = got_error(GOT_ERR_BAD_PACKET);
done:
	if (err) {
		int j;
		for (j = 0; j < i; j++) {
			free(tokens[j]);
			tokens[j] = NULL;
		}
	}
	return err;
}

const struct got_error *
got_gitproto_parse_refline(char **id_str, char **refname,
    char **server_capabilities, char *line, int len)
{
	const struct got_error *err = NULL;
	char *tokens[3];

	*id_str = NULL;
	*refname = NULL;
	/* don't reset *server_capabilities */

	err = tokenize_refline(tokens, line, len, nitems(tokens));
	if (err)
		return err;

	if (tokens[0])
		*id_str = tokens[0];
	if (tokens[1])
		*refname = tokens[1];
	if (tokens[2]) {
		if (*server_capabilities == NULL) {
			char *p;
			*server_capabilities = tokens[2];
			p = strrchr(*server_capabilities, '\n');
			if (p)
				*p = '\0';
		} else
			free(tokens[2]);
	}

	return NULL;
}

static const struct got_error *
match_capability(char **my_capabilities, const char *capa,
    const struct got_capability *mycapa)
{
	char *equalsign;
	char *s;

	equalsign = strchr(capa, '=');
	if (equalsign) {
		if (strncmp(capa, mycapa->key, equalsign - capa) != 0)
			return NULL;
	} else {
		if (strcmp(capa, mycapa->key) != 0)
			return NULL;
	}

	if (asprintf(&s, "%s %s%s%s",
	    *my_capabilities != NULL ? *my_capabilities : "",
	    mycapa->key,
	    mycapa->value != NULL ? "=" : "",
	    mycapa->value != NULL ? mycapa->value : "") == -1)
		return got_error_from_errno("asprintf");

	free(*my_capabilities);
	*my_capabilities = s;
	return NULL;
}

static const struct got_error *
add_symref(struct got_pathlist_head *symrefs, char *capa)
{
	const struct got_error *err = NULL;
	char *colon, *name = NULL, *target = NULL;

	/* Need at least "A:B" */
	if (strlen(capa) < 3)
		return NULL;

	colon = strchr(capa, ':');
	if (colon == NULL)
		return NULL;

	*colon = '\0';
	name = strdup(capa);
	if (name == NULL)
		return got_error_from_errno("strdup");

	target = strdup(colon + 1);
	if (target == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

	/* We can't validate the ref itself here. The main process will. */
	err = got_pathlist_append(symrefs, name, target);
done:
	if (err) {
		free(name);
		free(target);
	}
	return err;
}

const struct got_error *
got_gitproto_match_capabilities(char **common_capabilities,
    struct got_pathlist_head *symrefs, char *server_capabilities,
    const struct got_capability my_capabilities[], size_t ncapa)
{
	const struct got_error *err = NULL;
	char *capa, *equalsign;
	size_t i;

	*common_capabilities = NULL;
	do {
		capa = strsep(&server_capabilities, " ");
		if (capa == NULL)
			return NULL;

		equalsign = strchr(capa, '=');
		if (equalsign != NULL && symrefs != NULL &&
		    strncmp(capa, "symref", equalsign - capa) == 0) {
			err = add_symref(symrefs, equalsign + 1);
			if (err)
				break;
			continue;
		}

		for (i = 0; i < ncapa; i++) {
			err = match_capability(common_capabilities,
			    capa, &my_capabilities[i]);
			if (err)
				break;
		}
	} while (capa);

	if (*common_capabilities == NULL) {
		*common_capabilities = strdup("");
		if (*common_capabilities == NULL)
			err = got_error_from_errno("strdup");
	}
	return err;
}
