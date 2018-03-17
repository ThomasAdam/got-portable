/*
 * Copyright (c) 2018 Stefan Sperling <stsp@openbsd.org>
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

const struct got_error *
got_path_segment_count(int *count, const char *path)
{
	char *s = strdup(path), *p;

	*count = 0;

	if (s == NULL)
		return got_error(GOT_ERR_NO_MEM);

	do {
		p = strsep(&s, "/");
		if (s && *s != '/')
			(*count)++;
	} while (p);

	return NULL;
}

FILE *
got_opentemp(void)
{
	char name[PATH_MAX];
	int fd;
	FILE *f;

	if (strlcpy(name, "/tmp/got.XXXXXXXX", sizeof(name)) >= sizeof(name))
		return NULL;

	fd = mkstemp(name);
	if (fd < 0)
		return NULL;

	unlink(name);
	f = fdopen(fd, "w+");
	if (f == NULL) {
		close(fd);
		return NULL;
	}

	return f;
}

const struct got_error *
got_opentemp_named(char **path, FILE **outfile, const char *basepath)
{
	const struct got_error *err = NULL;
	int fd;

	if (asprintf(path, "%s-XXXXXX", basepath) == -1) {
		*path = NULL;
		return got_error(GOT_ERR_NO_MEM);
	}

	fd = mkstemp(*path);
	if (fd == -1) {
		err = got_error_from_errno();
		free(*path);
		*path = NULL;
		return err;
	}

	*outfile = fdopen(fd, "w+");
	if (*outfile == NULL) {
		err = got_error_from_errno();
		free(*path);
		*path = NULL;
	}

	return err;
}
