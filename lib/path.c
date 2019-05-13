/*
 * Copyright (c) 2018, 2019 Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2015 Theo de Raadt <deraadt@openbsd.org>
 * Copyright (c) 1997 Todd C. Miller <millert@openbsd.org>
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
#include <sys/stat.h>

#include <errno.h>
#include <limits.h>
#include <libgen.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <paths.h>

#include "got_error.h"
#include "got_path.h"

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

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

/* based on canonpath() from kern_pledge.c */
const struct got_error *
got_canonpath(const char *input, char *buf, size_t bufsize)
{
	const char *p;
	char *q;

	/* can't canon relative paths, don't bother */
	if (!got_path_is_absolute(input)) {
		if (strlcpy(buf, input, bufsize) >= bufsize)
			return got_error(GOT_ERR_NO_SPACE);
		return NULL;
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
		return NULL;
	} else
		return got_error(GOT_ERR_NO_SPACE);
}

const struct got_error *
got_path_skip_common_ancestor(char **child, const char *parent_abspath,
    const char *abspath)
{
	const struct got_error *err = NULL;
	size_t len_parent, len, bufsize;

	*child = NULL;

	len_parent = strlen(parent_abspath);
	len = strlen(abspath);
	if (len_parent >= len)
		return got_error(GOT_ERR_BAD_PATH);
	if (strncmp(parent_abspath, abspath, len_parent) != 0)
		return got_error(GOT_ERR_BAD_PATH);
	if (!got_path_is_root_dir(parent_abspath) && abspath[len_parent] != '/')
		return got_error(GOT_ERR_BAD_PATH);
	while (abspath[len_parent] == '/')
		abspath++;
	bufsize = len - len_parent + 1;
	*child = malloc(bufsize);
	if (*child == NULL)
		return got_error_from_errno("malloc");
	if (strlcpy(*child, abspath + len_parent, bufsize) >= bufsize) {
		err = got_error_from_errno("strlcpy");
		free(*child);
		*child = NULL;
		return err;
	}
	return NULL;
}

int
got_path_is_root_dir(const char *path)
{
	return (path[0] == '/' && path[1] == '\0');
}

int
got_path_is_current_dir(const char *path)
{
	return (path[0] == '.' && path[1] == '\0');
}

int
got_path_is_child(const char *child, const char *parent, size_t parent_len)
{
	if (parent_len == 0 || got_path_is_root_dir(parent))
		return 1;

	if (strncmp(parent, child, parent_len) != 0)
		return 0;
	if (child[parent_len] != '/')
		return 0;

	return 1;
}

int
got_path_cmp(const char *path1, const char *path2)
{
	size_t len1 = strlen(path1);
	size_t len2 = strlen(path2);
	size_t min_len = MIN(len1, len2);
	size_t i = 0;

	/* Leading directory separators are insignificant. */
	while (path1[0] == '/')
		path1++;
	while (path2[0] == '/')
		path2++;

	len1 = strlen(path1);
	len2 = strlen(path2);
	min_len = MIN(len1, len2);

	/* Skip over common prefix. */
	while (i < min_len && path1[i] == path2[i])
		i++;

	/* Are the paths exactly equal (besides path separators)? */
	if (len1 == len2 && i >= min_len)
		return 0;

	/* Skip over redundant trailing path seperators. */
	while (path1[i] == '/' && path1[i + 1] == '/')
		path1++;
	while (path2[i] == '/' && path2[i + 1] == '/')
		path2++;

	/* Trailing path separators are insignificant. */
	if (path1[i] == '/' && path1[i + 1] == '\0' && path2[i] == '\0')
		return 0;
	if (path2[i] == '/' && path2[i + 1] == '\0' && path1[i] == '\0')
		return 0;

	/* Order children in subdirectories directly after their parents. */
	if (path1[i] == '/' && path2[i] == '\0')
		return 1;
	if (path2[i] == '/' && path1[i] == '\0')
		return -1;
	if (path1[i] == '/' && path2[i] != '\0')
		return -1;
	if (path2[i] == '/' && path1[i] != '\0')
		return 1;

	/* Next character following the common prefix determines order. */
	return (unsigned char)path1[i] < (unsigned char)path2[i] ? -1 : 1;
}

const struct got_error *
got_pathlist_insert(struct got_pathlist_entry **inserted,
    struct got_pathlist_head *pathlist, const char *path, void *data)
{
	struct got_pathlist_entry *new, *pe;

	if (inserted)
		*inserted = NULL;

	new = malloc(sizeof(*new));
	if (new == NULL)
		return got_error_from_errno("malloc");
	new->path = path;
	new->data = data;

	/*
	 * Many callers will provide paths in a somewhat sorted order while
	 * constructing a path list from inputs such as tree objects or
	 * dirents. Iterating backwards from the tail of the list should
	 * be more efficient than traversing through the entire list each
	 * time an element is inserted.
	 */
	pe = TAILQ_LAST(pathlist, got_pathlist_head);
	while (pe) {
		int cmp = got_path_cmp(pe->path, path);
		if (cmp == 0) {
			free(new); /* duplicate */
			return NULL;
		} else if (cmp < 0) {
			TAILQ_INSERT_AFTER(pathlist, pe, new, entry);
			if (inserted)
				*inserted = new;
			return NULL;
		}
		pe = TAILQ_PREV(pe, got_pathlist_head, entry);
	}

	TAILQ_INSERT_HEAD(pathlist, new, entry);
	if (inserted)
		*inserted = new;
	return NULL;
}

void
got_pathlist_free(struct got_pathlist_head *pathlist)
{
	struct got_pathlist_entry *pe;

	while ((pe = TAILQ_FIRST(pathlist)) != NULL) {
		TAILQ_REMOVE(pathlist, pe, entry);
		free(pe);
	}
}

static const struct got_error *
make_parent_dirs(const char *abspath)
{
	const struct got_error *err = NULL;
	char *parent;

	err = got_path_dirname(&parent, abspath);
	if (err)
		return err;

	if (mkdir(parent, GOT_DEFAULT_DIR_MODE) == -1) {
		if (errno == ENOENT) {
			err = make_parent_dirs(parent);
			if (err)
				goto done;
			if (mkdir(parent, GOT_DEFAULT_DIR_MODE) == -1) {
				err = got_error_from_errno2("mkdir", parent);
				goto done;
			}
		} else
			err = got_error_from_errno2("mkdir", parent);
	}
done:
	free(parent);
	return err;
}

const struct got_error *
got_path_mkdir(const char *abspath)
{
	const struct got_error *err = NULL;

	if (mkdir(abspath, GOT_DEFAULT_DIR_MODE) == -1) {
		if (errno == ENOENT) {
			err = make_parent_dirs(abspath);
			if (err)
				goto done;
			if (mkdir(abspath, GOT_DEFAULT_DIR_MODE) == -1)
				err = got_error_from_errno2("mkdir", abspath);
		} else
			err = got_error_from_errno2("mkdir", abspath);
	}

done:
	return err;
}

int
got_path_dir_is_empty(const char *dir)
{
	DIR *d;
	struct dirent *dent;
	int empty = 1;

	d = opendir(dir);
	if (d == NULL)
		return 1;

	while ((dent = readdir(d)) != NULL) {
		if (strcmp(dent->d_name, ".") == 0 ||
		    strcmp(dent->d_name, "..") == 0)
			continue;

		empty = 0;
		break;
	}

	closedir(d);
	return empty;
}

const struct got_error *
got_path_dirname(char **parent, const char *path)
{
	char *p;

	p = dirname(path);
	if (p == NULL)
		return got_error_from_errno2("dirname", path);

	if (p[0] == '.' && p[1] == '\0')
		return got_error(GOT_ERR_BAD_PATH);

	*parent = strdup(p);
	if (*parent == NULL)
		return got_error_from_errno("strdup");

	return NULL;
}

void
got_path_strip_trailing_slashes(char *path)
{
	int x;

	while (path[x = strlen(path) - 1] == '/')
		path[x] = '\0';
}

/* based on findprog() from usr.sbin/which/which.c */
const struct got_error *
got_path_find_prog(char **filename, const char *prog)
{
	char *p;
	int len;
	struct stat sbuf;
	char *path, *pathcpy;

	*filename = NULL;

	path = getenv("PATH");
	if (path == NULL)
		path = _PATH_DEFPATH;

	/* Special case if prog contains '/' */
	if (strchr(prog, '/')) {
		if ((stat(prog, &sbuf) == 0) && S_ISREG(sbuf.st_mode) &&
		    access(prog, X_OK) == 0) {
			*filename = strdup(prog);
			if (*filename == NULL)
				return got_error_from_errno("strdup");
		}
		return NULL;
	}

	if ((path = strdup(path)) == NULL)
		return got_error_from_errno("strdup");
	pathcpy = path;

	while ((p = strsep(&pathcpy, ":")) != NULL) {
		if (*p == '\0')
			p = ".";

		len = strlen(p);
		while (len > 0 && p[len-1] == '/')
			p[--len] = '\0';	/* strip trailing '/' */

		if (asprintf(filename, "%s/%s", p, prog) == -1) {
			free(path);
			return got_error_from_errno("asprintf");
		}
		if ((stat(*filename, &sbuf) == 0) && S_ISREG(sbuf.st_mode) &&
		    access(*filename, X_OK) == 0) {
			free(path);
			return NULL;
		}
		free(*filename);
		*filename = NULL;
		continue;
	}
	free(path);
	return NULL;
}
