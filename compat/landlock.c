/*
 * Copyright (c) 2021 Omar Polo <op@openbsd.org>
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

#include <linux/landlock.h>

#include <sys/prctl.h>
#include <sys/syscall.h>

#include <errno.h>
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

/*
 * Maybe we should ship with a full copy of the linux headers because
 * you never know...
 */

#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER	(1ULL << 13)
#endif

#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE	(1ULL << 14)
#endif

/*
 * Revoke any fs access.
 */
int
landlock_no_fs(void)
{
	struct landlock_ruleset_attr rattr = {
		/* 
		 * List all capabilities currently defined by landlock.
		 * Failure in doing so will implicitly allow those actions
		 * (i.e. omitting READ_FILE will allow to read _any_ file.)
		 */
		.handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE |
				     LANDLOCK_ACCESS_FS_READ_FILE |
				     LANDLOCK_ACCESS_FS_READ_DIR |
				     LANDLOCK_ACCESS_FS_WRITE_FILE |
				     LANDLOCK_ACCESS_FS_REMOVE_DIR |
				     LANDLOCK_ACCESS_FS_REMOVE_FILE |
				     LANDLOCK_ACCESS_FS_MAKE_CHAR |
				     LANDLOCK_ACCESS_FS_MAKE_DIR |
				     LANDLOCK_ACCESS_FS_MAKE_REG |
				     LANDLOCK_ACCESS_FS_MAKE_SOCK |
				     LANDLOCK_ACCESS_FS_MAKE_FIFO |
				     LANDLOCK_ACCESS_FS_MAKE_BLOCK |
				     LANDLOCK_ACCESS_FS_MAKE_SYM |
				     LANDLOCK_ACCESS_FS_REFER |
				     LANDLOCK_ACCESS_FS_TRUNCATE,
	};
	int fd, abi, saved_errno;

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		return -1;

	abi = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
	if (abi == -1) {
		/* this kernel doesn't have landlock built in */
		if (errno == ENOSYS || errno == EOPNOTSUPP)
			return 0;
		return -1;
	}
	if (abi < 2)
		rattr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_REFER;
	if (abi < 3)
		rattr.handled_access_fs &= ~LANDLOCK_ACCESS_FS_TRUNCATE;

	fd = landlock_create_ruleset(&rattr, sizeof(rattr), 0);
	if (fd == -1)
		return -1;

	if (landlock_restrict_self(fd, 0)) {
		saved_errno = errno;
		close(fd);
		errno = saved_errno;
		return -1;
	}

	close(fd);
	return 0;
}
