/*
 * Copyright (c) 2018 Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2015 Theo de Raadt <deraadt@openbsd.org>
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

#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include "got_error.h"

#include "got_lib_path.h"

int
got_path_is_absolute(const char *path)
{
	return path[0] == '/';
}

char *
got_path_get_absolute(const char *relpath) 
{
	char cwd[PATH_MAX];
	char *abspath;

	if (getcwd(cwd, sizeof(cwd)) == NULL)
		return NULL;

	if (asprintf(&abspath, "%s/%s/", cwd, relpath) == -1)
		return NULL;

	return abspath;
}

char *
got_path_normalize(const char *path)
{
	char *resolved;

	resolved = realpath(path, NULL);
	if (resolved == NULL)
		return NULL;
	
	if (!got_path_is_absolute(resolved)) {
		char *abspath = got_path_get_absolute(resolved);
		free(resolved);
		resolved = abspath;
	}

	return resolved;
}

/* canonpath() from kern_pledge.c */
int
got_canonpath(const char *input, char *buf, size_t bufsize)
{
	const char *p;
	char *q;

	/* can't canon relative paths, don't bother */
	if (!got_path_is_absolute(input)) {
		if (strlcpy(buf, input, bufsize) >= bufsize)
			return ENAMETOOLONG;
		return 0;
	}

	p = input;
	q = buf;
	while (*p && (q - buf < bufsize)) {
		if (p[0] == '/' && (p[1] == '/' || p[1] == '\0')) {
			p += 1;

		} else if (p[0] == '/' && p[1] == '.' &&
		    (p[2] == '/' || p[2] == '\0')) {
			p += 2;

		} else if (p[0] == '/' && p[1] == '.' && p[2] == '.' &&
		    (p[3] == '/' || p[3] == '\0')) {
			p += 3;
			if (q != buf)	/* "/../" at start of buf */
				while (*--q != '/')
					continue;

		} else {
			*q++ = *p++;
		}
	}
	if ((*p == '\0') && (q - buf < bufsize)) {
		*q = 0;
		return 0;
	} else
		return ENAMETOOLONG;
}
