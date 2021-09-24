/*
 * Copyright (c) 2021 Omar Polo <op@omarpolo.com>
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

/*
 * This an implementation of an OpenBSD' unveil(2) compatible API on
 * top of Linux' landlock.
 */

#include <linux/landlock.h>
#include <linux/prctl.h>

#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

#include "got_compat.h"

/*
 * What's the deal with landlock?  While distro with linux >= 5.13
 * have the struct declarations, libc wrappers are missing.  The
 * sample landlock code provided by the authors includes these "shims"
 * in their example for the landlock API until libc provides them.
 */

#ifndef landlock_create_ruleset
static inline int
landlock_create_ruleset(const struct landlock_ruleset_attr *attr, size_t size,
    __u32 flags)
{
	return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
static inline int
landlock_add_rule(int ruleset_fd, enum landlock_rule_type type,
    const void *attr, __u32 flags)
{
	return syscall(__NR_landlock_add_rule, ruleset_fd, type, attr, flags);
}
#endif

#ifndef landlock_restrict_self
static inline int
landlock_restrict_self(int ruleset_fd, __u32 flags)
{
	return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

static int landlock_fd = -1;

static int
open_landlock(void)
{
	struct landlock_ruleset_attr rattr = {
		.handled_access_fs =	LANDLOCK_ACCESS_FS_EXECUTE	|
					LANDLOCK_ACCESS_FS_WRITE_FILE	|
					LANDLOCK_ACCESS_FS_READ_FILE	|
					LANDLOCK_ACCESS_FS_READ_DIR	|
					LANDLOCK_ACCESS_FS_REMOVE_DIR	|
					LANDLOCK_ACCESS_FS_REMOVE_FILE	|
					LANDLOCK_ACCESS_FS_MAKE_CHAR	|
					LANDLOCK_ACCESS_FS_MAKE_DIR	|
					LANDLOCK_ACCESS_FS_MAKE_REG	|
					LANDLOCK_ACCESS_FS_MAKE_SOCK	|
					LANDLOCK_ACCESS_FS_MAKE_FIFO	|
					LANDLOCK_ACCESS_FS_MAKE_BLOCK	|
					LANDLOCK_ACCESS_FS_MAKE_SYM,
	};

	return landlock_create_ruleset(&rattr, sizeof(rattr), 0);
}

static int
landlock_apply(void)
{
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		return -1;

	if (landlock_restrict_self(landlock_fd, 0))
		return -1;

	close(landlock_fd);
	landlock_fd = -1;
	return 0;
}

static int
parse_permissions(const char *permission)
{
	int perm = 0;

	for (; *permission; ++permission) {
		switch (*permission) {
		case 'r':
			perm |= LANDLOCK_ACCESS_FS_READ_FILE;
			perm |= LANDLOCK_ACCESS_FS_READ_DIR;
			break;
		case 'w':
			perm |= LANDLOCK_ACCESS_FS_WRITE_FILE;
			break;
		case 'x':
			perm |= LANDLOCK_ACCESS_FS_EXECUTE;
			break;
		case 'c':
			perm |= LANDLOCK_ACCESS_FS_REMOVE_DIR;
			perm |= LANDLOCK_ACCESS_FS_REMOVE_FILE;
			perm |= LANDLOCK_ACCESS_FS_MAKE_CHAR;
			perm |= LANDLOCK_ACCESS_FS_MAKE_DIR;
			perm |= LANDLOCK_ACCESS_FS_MAKE_REG;
			perm |= LANDLOCK_ACCESS_FS_MAKE_SOCK;
			perm |= LANDLOCK_ACCESS_FS_MAKE_FIFO;
			perm |= LANDLOCK_ACCESS_FS_MAKE_BLOCK;
			perm |= LANDLOCK_ACCESS_FS_MAKE_SYM;
			break;
		default:
			return -1;
		}
	}

	return perm;
}

static int
landlock_unveil_path(const char *path, int permissions)
{
	struct landlock_path_beneath_attr pb;
	struct stat sb;
	int fd, err, saved_errno;
	char fpath[PATH_MAX];

	pb.allowed_access = permissions;
	if ((pb.parent_fd = open(path, O_PATH)) == -1)
		return -1;

	if (fstat(pb.parent_fd, &sb) == -1)
		return -1;

	if (!S_ISDIR(sb.st_mode)) {
		close(pb.parent_fd);

		if (strlcpy(fpath, path, sizeof(fpath)) >= sizeof(fpath)) {
			errno = ENAMETOOLONG;
			return -1;
		}

		permissions |= LANDLOCK_ACCESS_FS_READ_FILE;
		permissions |= LANDLOCK_ACCESS_FS_READ_DIR;
		return landlock_unveil_path(dirname(fpath), permissions);
	}

	err = landlock_add_rule(landlock_fd, LANDLOCK_RULE_PATH_BENEATH,
	    &pb, 0);
	saved_errno = errno;
	close(pb.parent_fd);
	errno = saved_errno;
	return err ? -1 : 0;
}

int
landlock_unveil(const char *path, const char *permissions)
{
	int perms;

	if (landlock_fd == -1) {
		if ((landlock_fd = open_landlock()) == -1)
			return -1;

		/* XXX: use rpath on the current executable */
		if (landlock_unveil("/lib64", "rx") == -1)
			return -1;
	}

	if (path == NULL && permissions == NULL)
		return landlock_apply();

	if (path == NULL ||
	    permissions == NULL ||
	    (perms = parse_permissions(permissions)) == -1) {
		errno = EINVAL;
		return -1;
	}

	return landlock_unveil_path(path, perms);
}

int
landlock_no_fs(void)
{
	if ((landlock_fd = open_landlock()) == -1)
		return -1;

	return landlock_apply();
}
