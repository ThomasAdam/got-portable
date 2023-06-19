/*
 * Copyright (c) 2019 Stefan Sperling <stsp@openbsd.org>
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

#include "got_compat.h"

#include <sys/stat.h>
#include <sys/queue.h>

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include "got_error.h"
#include "got_path.h"

#include "got_lib_lockfile.h"

const struct got_error *
got_lockfile_lock(struct got_lockfile **lf, const char *path, int dir_fd)
{
	const struct got_error *err = NULL;
	int attempts = 5;

	*lf = calloc(1, sizeof(**lf));
	if (*lf == NULL)
		return got_error_from_errno("calloc");
	(*lf)->fd = -1;

	(*lf)->locked_path = strdup(path);
	if ((*lf)->locked_path == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

	if (asprintf(&(*lf)->path, "%s%s", path, GOT_LOCKFILE_SUFFIX) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	do {
		if (dir_fd != -1) {
			(*lf)->fd = openat(dir_fd, (*lf)->path,
			    O_RDWR | O_CREAT | O_EXCL | O_EXLOCK | O_CLOEXEC,
			    GOT_DEFAULT_FILE_MODE);
		} else {
			(*lf)->fd = open((*lf)->path,
			    O_RDWR | O_CREAT | O_EXCL | O_EXLOCK | O_CLOEXEC,
			    GOT_DEFAULT_FILE_MODE);
		}
		if ((*lf)->fd != -1)
			break;
		if (errno != EEXIST) {
			err = got_error_from_errno2("open", (*lf)->path);
			goto done;
		}
		sleep(1);
	} while (--attempts > 0);

	if ((*lf)->fd == -1)
		err = got_error(GOT_ERR_LOCKFILE_TIMEOUT);
done:
	if (err) {
		got_lockfile_unlock(*lf, dir_fd);
		*lf = NULL;
	}
	return err;
}

const struct got_error *
got_lockfile_unlock(struct got_lockfile *lf, int dir_fd)
{
	const struct got_error *err = NULL;

	if (dir_fd != -1) {
		if (lf->path && lf->fd != -1 &&
		    unlinkat(dir_fd, lf->path, 0) != 0)
			err = got_error_from_errno("unlinkat");
	} else if (lf->path && lf->fd != -1 && unlink(lf->path) != 0)
		err = got_error_from_errno("unlink");
	if (lf->fd != -1 && close(lf->fd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	free(lf->path);
	free(lf->locked_path);
	free(lf);
	return err;
}
