/*
 * Copyright (c) 2025 Stefan Sperling <stsp@openbsd.org>
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
#include <sys/tree.h>
#include <sys/queue.h>

#include <ctype.h>
#include <imsg.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "got_error.h"
#include "got_path.h"

#include "gotsys.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

void
gotsys_conf_init(struct gotsys_conf *gotsysconf)
{
	memset(gotsysconf, 0, sizeof(*gotsysconf));

	STAILQ_INIT(&gotsysconf->users);
	STAILQ_INIT(&gotsysconf->groups);
	TAILQ_INIT(&gotsysconf->repos);
}

void
gotsys_authorized_key_free(struct gotsys_authorized_key *key)
{
	if (key == NULL)
		return;

	free(key->keytype);
	free(key->key);
	free(key->comment);
	free(key);
}

void
gotsys_authorized_keys_list_purge(struct gotsys_authorized_keys_list *keys)
{

	if (keys == NULL)
		return;

	while (!STAILQ_EMPTY(keys)) {
		struct gotsys_authorized_key *key;

		key = STAILQ_FIRST(keys);
		STAILQ_REMOVE_HEAD(keys, entry);
		gotsys_authorized_key_free(key);
	}
}

void
gotsys_user_free(struct gotsys_user *user)
{
	if (user == NULL)
		return;

	free(user->name);
	free(user->password);
	gotsys_authorized_keys_list_purge(&user->authorized_keys);
	free(user);
}

void
gotsys_group_free(struct gotsys_group *group)
{
	if (group == NULL)
		return;

	while (!STAILQ_EMPTY(&group->members)) {
		struct gotsys_user *member;

		member = STAILQ_FIRST(&group->members);
		STAILQ_REMOVE_HEAD(&group->members, entry);
		gotsys_user_free(member);
	}

	free(group->name);
	free(group);
}

void
gotsys_access_rule_free(struct gotsys_access_rule *rule)
{
	if (rule == NULL)
		return;

	free(rule->identifier);
	free(rule);
}

void
gotsys_notification_target_free(struct gotsys_notification_target *target)
{
	if (target == NULL)
		return;

	switch (target->type) {
	case GOTSYS_NOTIFICATION_VIA_EMAIL:
		free(target->conf.email.sender);
		free(target->conf.email.recipient);
		free(target->conf.email.responder);
		free(target->conf.email.hostname);
		free(target->conf.email.port);
		break;
	case GOTSYS_NOTIFICATION_VIA_HTTP:
		free(target->conf.http.hostname);
		free(target->conf.http.port);
		free(target->conf.http.path);
		free(target->conf.http.user);
		free(target->conf.http.password);
		free(target->conf.http.hmac_secret);
		break;
	default:
		abort();
		/* NOTREACHED */
	}

	free(target);
}

void
gotsys_repo_free(struct gotsys_repo *repo)
{
	if (repo == NULL)
		return;

	while (!STAILQ_EMPTY(&repo->access_rules)) {
		struct gotsys_access_rule *rule;

		rule = STAILQ_FIRST(&repo->access_rules);
		STAILQ_REMOVE_HEAD(&repo->access_rules, entry);
		gotsys_access_rule_free(rule);
	}

	got_pathlist_free(&repo->protected_tag_namespaces,
	    GOT_PATHLIST_FREE_PATH);
	got_pathlist_free(&repo->protected_branch_namespaces,
	    GOT_PATHLIST_FREE_PATH);
	got_pathlist_free(&repo->protected_branches, GOT_PATHLIST_FREE_PATH);
	got_pathlist_free(&repo->notification_refs, GOT_PATHLIST_FREE_PATH);
	got_pathlist_free(&repo->notification_ref_namespaces,
	    GOT_PATHLIST_FREE_PATH);
	
	while (!STAILQ_EMPTY(&repo->notification_targets)) {
		struct gotsys_notification_target *target;

		target = STAILQ_FIRST(&repo->notification_targets);
		STAILQ_REMOVE_HEAD(&repo->notification_targets, entry);
		gotsys_notification_target_free(target);
	}
}

void
gotsys_userlist_purge(struct gotsys_userlist *users)
{
	while (!STAILQ_EMPTY(users)) {
		struct gotsys_user *user;

		user = STAILQ_FIRST(users);
		STAILQ_REMOVE_HEAD(users, entry);
		gotsys_user_free(user);
	}
}

void
gotsys_grouplist_purge(struct gotsys_grouplist *groups)
{
	while (!STAILQ_EMPTY(groups)) {
		struct gotsys_group *group;

		group = STAILQ_FIRST(groups);
		STAILQ_REMOVE_HEAD(groups, entry);
		gotsys_group_free(group);
	}
}

void
gotsys_conf_clear(struct gotsys_conf *gotsysconf)
{
	gotsys_userlist_purge(&gotsysconf->users);

	gotsys_grouplist_purge(&gotsysconf->groups);

	while (!TAILQ_EMPTY(&gotsysconf->repos)) {
		struct gotsys_repo *repo;

		repo = TAILQ_FIRST(&gotsysconf->repos);
		TAILQ_REMOVE(&gotsysconf->repos, repo, entry);
		gotsys_repo_free(repo);
	}
}

static const char *wellknown_users[] = {
	"anonymous",
	"root",
	"daemon",
	"operator",
	"bin",
	"build",
	"sshd",
	"www",
	"nobody",
};

static const char *wellknown_groups[] = {
	"wheel",
	"daemon",
	"kmem",
	"sys",
	"tty",
	"operator",
	"bin",
	"wsrc",
	"users",
	"auth",
	"games",
	"staff",
	"wobj",
	"sshd",
	"guest",
	"utmp",
	"crontab",
	"www",
	"network",
	"authpf",
	"dialer",
	"nogroup",
	"nobody",
};

const struct got_error *
gotsys_conf_validate_name(const char *name, const char *type)
{
	size_t i, len;

	if (name[0] == '\0')
		return got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "empty %s name", type);

	/* Forbid use of well-known names, regardless of requested type. */
	for (i = 0; i < nitems(wellknown_users); i++) {
		if (strcmp(name, wellknown_users[i]) == 0) {
			return got_error_fmt(GOT_ERR_PARSE_CONFIG,
			    "%s name '%s' is reserved and cannot be used",
			    type, name);
		}
	}
	for (i = 0; i < nitems(wellknown_groups); i++) {
		if (strcmp(name, wellknown_groups[i]) == 0) {
			return got_error_fmt(GOT_ERR_PARSE_CONFIG,
			    "%s name '%s' is reserved and cannot be used",
			    type, name);
		}
	}

	/*
	 * Quoting useradd(3):
	 *
	 * It is recommended that login names contain only lowercase
	 * characters and digits.  They may also contain uppercase
	 * characters, non-leading hyphens, periods, underscores, and a
	 * trailing ‘$’.  Login names may not be longer than 31 characters.
	 */
	len = strlen(name);
	if (len > _PW_NAME_LEN) {
		return got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "%s name is too long (exceeds %d bytes): %s",
		    type, _PW_NAME_LEN, name);
	}

	/*
	 * In addition to the regular useradd(3) rules above, disallow
	 * leading digits to prevent a name from being misinterpreted
	 * as a number in any context by any tool.
	 */
	if (isdigit(name[0]))
		goto invalid;

	/*
	 * In addition to the regular useradd(3) rules above, disallow
	 * leading underscores to prevent collisions with system daemon
	 * accounts.
	 * Prevent leading periods as well, because we can.
	 * A trailing $ is required for compat with Samba. We prevent it
	 * for now until interaction with Samba is proven to be useful.
	 */
	for (i = 0; i < len; i++) {
		/*
		 * On non-OpenBSD systems, isalnum(3) can suffer from
		 * locale-dependent-behaviour syndrom.
		 * Prevent non-ASCII characters in a portable way.
		 */
		if (name[i] & 0x80)
			goto invalid;

		if (isalnum(name[i]) ||
		    (i > 0 && name[i] == '-') ||
		    (i > 0 && name[i] == '_') ||
		    (i > 0 && name[i] == '.'))
			continue;

		goto invalid;
	}

	return NULL;

invalid:
	return got_error_fmt(GOT_ERR_PARSE_CONFIG,
	    "%s names may only contain alphabetic ASCII "
	    "characters, non-leading digits, non-leading hyphens, "
	    "non-leading underscores, or non-leading periods: %s",
	    type, name);
}

const struct got_error *
gotsys_conf_validate_repo_name(const char *name)
{
	size_t len, i;

	if (name[0] == '\0')
		return got_error_msg(GOT_ERR_PARSE_CONFIG,
		    "empty repository name");

	/*
	 * Disallow leading digits to prevent a name from being
	 * misinterpreted as a number in any context by any tool.
	 */
	if (isdigit(name[0]))
		goto invalid;

	len = strlen(name);
	for (i = 0; i < len; i++) {
		if (isalnum(name[i]) ||
		    (i > 0 && name[i] == '-') ||
		    (i > 0 && name[i] == '_') ||
		    (i > 0 && name[i] == '.'))
			continue;

		goto invalid;
	}

	return NULL;

invalid:
	return got_error_fmt(GOT_ERR_PARSE_CONFIG,
	    "repository names may only contain alphabetic ASCII "
	    "characters, non-leading digits, non-leading hyphens, "
	    "non-leading underscores, or non-leading periods: %s",
	    name);
}

static int
validate_password(const char *s, size_t len)
{
	static const u_int8_t base64chars[] =
	    "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	size_t i;

	for (i = 0; i < len; i++) {
		if (strchr(base64chars, s[i]) == NULL)
			return 0;
	}

	return 1;
}


const struct got_error *
gotsys_conf_validate_password(const char *username, const char *password)
{
	size_t len = strlen(password);

	if (len < 8 || len > _PASSWORD_LEN)
		goto invalid;

	if (password[0] != '$' ||
	    password[1] != '2' || /* bcrypt version */
	    !(password[2] == 'a' || password[2] == 'b') || /* minor versions */
	    password[3] != '$' ||
	    !(isdigit(password[4]) && isdigit(password[5])) || /* num rounds */
	    password[6] != '$')
		goto invalid;

	/* The remainder must be base64 data. */
	if (!validate_password(&password[7], len - 7))
		goto invalid;

	return NULL;

invalid:
	return got_error_fmt(GOT_ERR_PARSE_CONFIG, "password for user %s "
	    "was not encrypted with the encrypt(1) utility", username);
}

static const struct got_error *
validate_comment(const char *comment, size_t len)
{
	size_t i;

	/* Require printable ASCII characters. */	
	for (i = 0; i < len; i++) {
		/*
		 * On non-OpenBSD systems, isalnum(3) can suffer from
		 * locale-dependent-behaviour syndrom.
		 * Prevent non-ASCII characters in a portable way.
		 */
		if (comment[i] & 0x80)
			goto invalid;

		if (!isalnum(comment[i]) && !ispunct(comment[i]))
			goto invalid;
	}

	return NULL;
invalid:
	return got_error_fmt(GOT_ERR_PARSE_CONFIG,
	    "authorized key comments may only contain "
	    "printable ASCII characters and no whitespace");
}

static int
validate_authorized_key(const char *s, size_t len)
{
	static const u_int8_t base64chars[] =
	    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
	size_t i;

	for (i = 0; i < len; i++) {
		if (strchr(base64chars, s[i]) == NULL)
			return 0;
	}

	return 1;
}

const struct got_error *
gotsys_conf_new_authorized_key(struct gotsys_authorized_key **key,
    char *keytype, char *keydata, char *comment)
{
	const struct got_error *err = NULL;
	static const char *known_keytypes[] = {
		"sk-ecdsa-sha2-nistp256@openssh.com",
		"ecdsa-sha2-nistp256",
		"ecdsa-sha2-nistp384",
		"ecdsa-sha2-nistp521",
		"sk-ssh-ed25519@openssh.com",
		"ssh-ed25519",
		"ssh-rsa"
	};
	size_t i, typelen, datalen, commentlen = 0, totlen;

	*key = NULL;

	for (i = 0; i < nitems(known_keytypes); i++) {
		if (strcmp(keytype, known_keytypes[i]) == 0)
			break;
	}
	if (i >= nitems(known_keytypes)) {
		return got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "unknown authorized key type: %s", keytype);
	}

	typelen = strlen(keytype);
	if (typelen > GOTSYS_AUTHORIZED_KEY_MAXLEN) {
		return got_error_fmt(GOT_ERR_NO_SPACE,
		    "authorized key type too long: %s", keytype);
	}

	datalen = strlen(keydata);
	if (datalen == 0) {
		return got_error_msg(GOT_ERR_AUTHORIZED_KEY,
		    "empty authorized key");
	}
	if (datalen > GOTSYS_AUTHORIZED_KEY_MAXLEN ||
	    typelen + datalen > GOTSYS_AUTHORIZED_KEY_MAXLEN) {
		return got_error_fmt(GOT_ERR_NO_SPACE,
		    "authorized key too long: %s:", keydata);
	}
	if (!validate_authorized_key(keydata, datalen)) {
		return got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "authorized key data must be base64-encoded");
	}

	if (comment) {
		commentlen = strlen(comment);
		if (commentlen > GOTSYS_AUTHORIZED_KEY_MAXLEN) {
			return got_error_fmt(GOT_ERR_NO_SPACE,
			    "authorized key comment too long: %s:",
			    comment);
		}

		err = validate_comment(comment, commentlen);
		if (err)
			return err;
	}

	/* Won't overflow since values are < GOTSYS_AUTHORIZED_KEY_MAXLEN. */
	totlen = typelen + datalen + commentlen;
	if (totlen > GOTSYS_AUTHORIZED_KEY_MAXLEN) {
		return got_error_fmt(GOT_ERR_NO_SPACE,
		    "authorized key too long: %s %s %s",
		    keytype, keydata, comment ? comment : "");
	}

	*key = calloc(1, sizeof(**key));
	if (*key == NULL)
		return got_error_from_errno("calloc");

	(*key)->keytype = strdup(keytype);
	if ((*key)->keytype == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

	(*key)->key = strdup(keydata);
	if ((*key)->key == NULL) {
		err = got_error_from_errno("strdup");
		goto done;
	}

	if (comment) {
		(*key)->comment = strdup(comment);
		if ((*key)->comment == NULL) {
			err = got_error_from_errno("strdup");
			goto done;
		}
	}
done:
	if (err) {
		gotsys_authorized_key_free(*key);
		*key = NULL;
	}
	return NULL;
}

const struct got_error *
gotsys_conf_new_user(struct gotsys_user **user, const char *username)
{
	const struct got_error *err;

	*user = NULL;

	err = gotsys_conf_validate_name(username, "user");
	if (err)
		return err;

	*user = calloc(1, sizeof(**user));
	if (*user == NULL)
		return got_error_from_errno("calloc");

	(*user)->name = strdup(username);
	if ((*user)->name == NULL) {
		err = got_error_from_errno("strdup");
		free(*user);
		*user = NULL;
		return err;
	}

	STAILQ_INIT(&(*user)->authorized_keys);
	return NULL;
}

const struct got_error *
gotsys_conf_new_group(struct gotsys_group **group, const char *groupname)
{
	const struct got_error *err;

	*group = NULL;

	err = gotsys_conf_validate_name(groupname, "group");
	if (err)
		return err;

	*group = calloc(1, sizeof(**group));
	if (*group == NULL)
		return got_error_from_errno("calloc");

	(*group)->name = strdup(groupname);
	if ((*group)->name == NULL) {
		err = got_error_from_errno("strdup");
		free(*group);
		*group = NULL;
		return err;
	}

	STAILQ_INIT(&(*group)->members);
	return NULL;
}

const struct got_error *
gotsys_conf_new_group_member(struct gotsys_grouplist *groups,
    const char *groupname, const char *username)
{
	struct gotsys_group *group = NULL;
	struct gotsys_user *member = NULL;

	STAILQ_FOREACH(group, groups, entry) {
		if (strcmp(group->name, groupname) == 0)
			break;
	}
	if (group == NULL) {
		return got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "reference to undeclared group '%s' via user '%s'",
		    groupname, username);
	}

	STAILQ_FOREACH(member, &group->members, entry) {
		if (strcmp(member->name, username) == 0)
			break;
	}
	if (member)
		return NULL;

	member = calloc(1, sizeof(*member));
	if (member == NULL)
		return got_error_from_errno("calloc");

	member->name = strdup(username);
	if (member->name == NULL) {
		free(member);
		return got_error_from_errno("strdup");
	}

	STAILQ_INSERT_TAIL(&group->members, member, entry);
	return NULL;
}

const struct got_error *
gotsys_conf_new_repo(struct gotsys_repo **new_repo, const char *name)
{
	const struct got_error *err = NULL;
	struct gotsys_repo *repo;

	*new_repo = NULL;

	err = gotsys_conf_validate_repo_name(name);
	if (err)
		return err;

	repo = calloc(1, sizeof(*repo));
	if (repo == NULL)
		return got_error_from_errno("calloc");

	STAILQ_INIT(&repo->access_rules);
	RB_INIT(&repo->protected_tag_namespaces);
	RB_INIT(&repo->protected_branch_namespaces);
	RB_INIT(&repo->protected_branches);
	RB_INIT(&repo->notification_refs);
	RB_INIT(&repo->notification_ref_namespaces);
	STAILQ_INIT(&repo->notification_targets);

	if (strlcpy(repo->name, name, sizeof(repo->name)) >=
	    sizeof(repo->name)) {
		free(repo);
		return got_error_fmt(GOT_ERR_BAD_PATH,
		    "repository name too long: %s", name);
	}

	*new_repo = repo;
	return NULL;
}

const struct got_error *
gotsys_conf_new_access_rule(struct gotsys_access_rule **rule,
    enum gotsys_access access, int authorization, const char *identifier,
    struct gotsys_userlist *users, struct gotsys_grouplist *groups)
{
	const struct got_error *err = NULL;
	const char *name;

	*rule = NULL;

	switch (access) {
	case GOTSYS_ACCESS_PERMITTED:
		if (authorization == 0) {
			return got_error_msg(GOT_ERR_PARSE_CONFIG,
			    "permit access rule without read or write "
			    "authorization");
		}
		break;
	case GOTSYS_ACCESS_DENIED:
		if (authorization != 0) {
			return got_error_msg(GOT_ERR_PARSE_CONFIG,
			    "deny access rule with read or write "
			    "authorization");
		}
		break;
	default:
		return got_error_msg(GOT_ERR_PARSE_CONFIG,
		    "invalid access rule");
	}

	if (authorization & ~(GOTSYS_AUTH_READ | GOTSYS_AUTH_WRITE)) {
		return got_error_msg(GOT_ERR_PARSE_CONFIG,
		    "invalid access rule authorization flags");
	}

	name = identifier;
	if (name[0] == '\0')
		return got_error_fmt(GOT_ERR_PARSE_CONFIG,
		    "empty identifier in access rule");

	if (name[0] == ':') {
		struct gotsys_group *group = NULL;

		name++;
		if (name[0] == '\0')
			return got_error_fmt(GOT_ERR_PARSE_CONFIG,
			    "empty group name in access rule");

		STAILQ_FOREACH(group, groups, entry) {
			if (strcmp(group->name, name) == 0)
				break;
		}
		if (group == NULL) {
			return got_error_fmt(GOT_ERR_PARSE_CONFIG,
			    "reference to undeclared group '%s' via "
			    "access rule", name);
		}
	} else if (strcmp(name, "anonymous") != 0) {
		struct gotsys_user *user = NULL;

		STAILQ_FOREACH(user, users, entry) {
			if (strcmp(user->name, name) == 0)
				break;
		}
		if (user == NULL) {
			return got_error_fmt(GOT_ERR_PARSE_CONFIG,
			    "reference to undeclared user '%s' via "
			    "access rule", name);
		}
	}

	*rule = calloc(1, sizeof(**rule));
	if (*rule == NULL)
		return got_error_from_errno("calloc");

	(*rule)->access = access;
	(*rule)->authorization = authorization;
	(*rule)->identifier = strdup(identifier);
	if ((*rule)->identifier == NULL) {
		err = got_error_from_errno("strdup");
		gotsys_access_rule_free(*rule);
		*rule = NULL;
	}

	return err;
}
