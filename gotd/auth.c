/*
 * Copyright (c) 2022 Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2015 Ted Unangst <tedu@openbsd.org>
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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/uio.h>

#include <errno.h>
#include <event.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#include <sha1.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <imsg.h>
#include <unistd.h>

#include "got_error.h"

#include "gotd.h"
#include "log.h"
#include "auth.h"

static int
parseuid(const char *s, uid_t *uid)
{
	struct passwd *pw;
	const char *errstr;

	if ((pw = getpwnam(s)) != NULL) {
		*uid = pw->pw_uid;
		if (*uid == UID_MAX)
			return -1;
		return 0;
	}
	*uid = strtonum(s, 0, UID_MAX - 1, &errstr);
	if (errstr)
		return -1;
	return 0;
}

static int
uidcheck(const char *s, uid_t desired)
{
	uid_t uid;

	if (parseuid(s, &uid) != 0)
		return -1;
	if (uid != desired)
		return -1;
	return 0;
}

static int
parsegid(const char *s, gid_t *gid)
{
	struct group *gr;
	const char *errstr;

	if ((gr = getgrnam(s)) != NULL) {
		*gid = gr->gr_gid;
		if (*gid == GID_MAX)
			return -1;
		return 0;
	}
	*gid = strtonum(s, 0, GID_MAX - 1, &errstr);
	if (errstr)
		return -1;
	return 0;
}

static int
match_identifier(const char *identifier, gid_t *groups, int ngroups,
    uid_t euid, gid_t egid)
{
	int i;

	if (identifier[0] == ':') {
		gid_t rgid;
		if (parsegid(identifier + 1, &rgid) == -1)
			return 0;
		if (rgid == egid)
			return 1;
		for (i = 0; i < ngroups; i++) {
			if (rgid == groups[i])
				break;
		}
		if (i == ngroups)
			return 0;
	} else if (uidcheck(identifier, euid) != 0)
		return 0;

	return 1;
}

const struct got_error *
gotd_auth_check(struct gotd_access_rule_list *rules, const char *repo_name,
    uid_t euid, gid_t egid, int required_auth)
{
	struct gotd_access_rule *rule;
	enum gotd_access access = GOTD_ACCESS_DENIED;
	struct passwd *pw;
	gid_t groups[NGROUPS_MAX];
	int ngroups = NGROUPS_MAX;

	pw = getpwuid(euid);
	if (pw == NULL)
		return got_error_from_errno("getpwuid");

	if (getgrouplist(pw->pw_name, pw->pw_gid, groups, &ngroups) == -1)
		log_warnx("group membership list truncated");

	STAILQ_FOREACH(rule, rules, entry) {
		if (!match_identifier(rule->identifier, groups, ngroups,
		    euid, egid))
			continue;

		access = rule->access;
		if (rule->access == GOTD_ACCESS_PERMITTED &&
		    (rule->authorization & required_auth) != required_auth)
			access = GOTD_ACCESS_DENIED;
	}

	if (access == GOTD_ACCESS_DENIED)
		return got_error_set_errno(EACCES, repo_name);

	if (access == GOTD_ACCESS_PERMITTED)
		return NULL;

	/* should not happen, this would be a bug */
	return got_error_msg(GOT_ERR_NOT_IMPL, "bad access rule");
}
