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
#include <sys/queue.h>
#include <sys/tree.h>

#include <event.h>
#include <imsg.h>
#include <limits.h>
#include <pwd.h>
#include <sha1.h>
#include <sha2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "got_error.h"
#include "got_path.h"
#include "got_object.h"

#include "gotsysd.h"
#include "gotsys.h"

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

const struct got_error *
gotsys_imsg_send_users(struct gotsysd_imsgev *iev,
    struct gotsys_userlist *users, int imsg_type, int imsg_done_type,
    int send_passwords)
{
	const struct got_error *err;
	struct gotsys_user *u;
	size_t totlen, remain, mlen;
	const size_t maxmesg  = MAX_IMSGSIZE - IMSG_HEADER_SIZE;
	struct gotsysd_imsg_sysconf_user iuser;
	struct ibuf *wbuf = NULL;

	u = STAILQ_FIRST(users);
	totlen = 0;
	while (u) {
		size_t namelen, pwlen = 0, ulen;

		namelen = strlen(u->name);
		if (send_passwords)
			pwlen = (u->password ? strlen(u->password) : 0);
		if (namelen + pwlen < namelen) {
			return got_error_msg(GOT_ERR_NO_SPACE,
			    "user name/password length overflow");
		}

		ulen = namelen + pwlen;
		if (totlen > INT_MAX - sizeof(iuser) - ulen) {
			return got_error_msg(GOT_ERR_NO_SPACE,
			    "user data length overflow");
		}

		totlen += sizeof(iuser) + ulen;
		u = STAILQ_NEXT(u, entry);
	}
	if (totlen == 0)
		return NULL;

	u = STAILQ_FIRST(users);
	remain = totlen;
	mlen = 0;
	while (u) {
		size_t ulen;

		iuser.name_len = strlen(u->name);
		iuser.password_len = (send_passwords && u->password ?
		    strlen(u->password) : 0);

		ulen = iuser.name_len + iuser.password_len;

		if (wbuf != NULL && mlen + sizeof(iuser) + ulen > maxmesg) {
			imsg_close(&iev->ibuf, wbuf);
			err = gotsysd_imsg_flush(&iev->ibuf);
			if (err)
				return err;
			wbuf = NULL;
			mlen = 0;
		}

		if (wbuf == NULL) {
			wbuf = imsg_create(&iev->ibuf, imsg_type, 0, 0,
			    MIN(remain, maxmesg));
			if (wbuf == NULL) {
				return got_error_from_errno_fmt(
				    "imsg_create %d", imsg_type);
			}
		}

		if (imsg_add(wbuf, &iuser, sizeof(iuser)) == -1)
			return got_error_from_errno_fmt("imsg_add %d",
			    imsg_type);
		if (imsg_add(wbuf, u->name, iuser.name_len) == -1)
			return got_error_from_errno_fmt("imsg_add %d",
			    imsg_type);
		if (imsg_add(wbuf, u->password, iuser.password_len) == -1)
			return got_error_from_errno_fmt("imsg_add %d",
			    imsg_type);

		remain -= sizeof(iuser) + ulen;
		mlen += sizeof(iuser) + ulen;
		u = STAILQ_NEXT(u, entry);
	}

	imsg_close(&iev->ibuf, wbuf);
	err = gotsysd_imsg_flush(&iev->ibuf);
	if (err)
		return err;

	if (gotsysd_imsg_compose_event(iev, imsg_done_type, 0,
	    -1, NULL, 0) == -1)
		return got_error_from_errno_fmt("imsg_compose %d",
		    imsg_done_type);
	
	return NULL;
}

const struct got_error *
gotsys_imsg_recv_users(struct imsg *imsg, struct gotsys_userlist *users)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsg_sysconf_user iuser;
	struct gotsys_user *user = NULL;
	char *name = NULL;
	size_t datalen, offset, remain;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(iuser))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	remain = datalen;
	offset = 0;
	while (remain > 0) {
		size_t namelen, pwlen, ulen;

		if (remain < sizeof(iuser))
			return got_error(GOT_ERR_PRIVSEP_LEN);

		memcpy(&iuser, imsg->data + offset, sizeof(iuser));

		namelen = iuser.name_len;
		if (namelen <= 0 || namelen > _PW_NAME_LEN)
			return got_error(GOT_ERR_PRIVSEP_LEN);
		pwlen = iuser.password_len;
		if (pwlen > _PASSWORD_LEN)
			return got_error(GOT_ERR_PRIVSEP_LEN);

		if (namelen + pwlen < namelen ||
		    namelen + pwlen < namelen || 
		    namelen + pwlen < namelen + pwlen) {
			return got_error_msg(GOT_ERR_NO_SPACE,
			    "user name/password/sshpubkey length overflow");
		}

		ulen = namelen + pwlen;
		if (sizeof(iuser) + ulen < sizeof(iuser)) {
			return got_error_msg(GOT_ERR_NO_SPACE,
			    "user data length overflow");
		}
		if (sizeof(iuser) + ulen > remain)
			return got_error(GOT_ERR_PRIVSEP_LEN);

		name = strndup(imsg->data + offset + sizeof(iuser), namelen);
		if (name == NULL)
			return got_error_from_errno("strndup");
		if (strlen(name) != namelen) {
			free(name);
			return got_error(GOT_ERR_PRIVSEP_LEN);
		}
		STAILQ_FOREACH(user, users, entry) {
			if (strcmp(name, user->name) == 0)
				break;
		}
		if (user != NULL) {
			free(name);
			name = NULL;
			user = NULL;
			continue;
		}

		err = gotsys_conf_validate_name(name, "user");
		if (err) {
			free(name);
			return err;
		}

		err = gotsys_conf_new_user(&user, name);
		free(name);
		name = NULL;
		if (err)
			return err;

		if (pwlen) {
			user->password = strndup(imsg->data + offset +
			    sizeof(iuser) + namelen, pwlen);
			if (user->password == NULL) {
				err = got_error_from_errno("strndup");
				gotsys_user_free(user);
				return err;
			}
			if (strlen(user->password) != pwlen) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				gotsys_user_free(user);
				return err;
			}
		}
#if 0
		log_debug("user %s: password '%s' ssh key '%s'", user->name,
		    user->password ? user->password : "",
		    user->ssh_pubkey ? user->ssh_pubkey : "");
#endif
		STAILQ_INSERT_TAIL(users, user, entry);
		user = NULL;

		offset += sizeof(iuser) + ulen;
		remain -= sizeof(iuser) + ulen;
	}

	return NULL;
}

const struct got_error *
gotsys_imsg_send_groups(struct gotsysd_imsgev *iev,
    struct gotsys_grouplist *groups, int imsg_group_type,
    int imsg_group_members_type, int imsg_group_members_done_type,
    int imsg_done_type)
{
	const struct got_error *err;
	struct gotsys_group *g;
	struct gotsysd_imsg_sysconf_group igroup;
	struct ibuf *wbuf = NULL;

	g = STAILQ_FIRST(groups);
	while (g) {
		igroup.name_len = strlen(g->name);

		wbuf = imsg_create(&iev->ibuf, imsg_group_type,
		    0, 0, sizeof(igroup) + igroup.name_len);
		if (wbuf == NULL) {
			return got_error_from_errno(
			    "imsg_create SYSCONF_GROUP");
		}

		if (imsg_add(wbuf, &igroup, sizeof(igroup)) == -1) {
			return got_error_from_errno_fmt("imsg_add %d",
			    imsg_group_type);
		}
		if (imsg_add(wbuf, g->name, igroup.name_len) == -1) {
			return got_error_from_errno_fmt("imsg_add %d",
			    imsg_group_type);
		}

		imsg_close(&iev->ibuf, wbuf);
		err = gotsysd_imsg_flush(&iev->ibuf);
		if (err)
			return err;

		err = gotsys_imsg_send_users(iev, &g->members,
		    imsg_group_members_type,
		    imsg_group_members_done_type, 0);
		if (err)
			return err;

		g = STAILQ_NEXT(g, entry);
	}

	if (gotsysd_imsg_compose_event(iev, imsg_done_type,
	    0, -1, NULL, 0) == -1) {
		return got_error_from_errno_fmt("imsg_compose %d",
		    imsg_done_type);
	}
	
	return NULL;
}

const struct got_error *
gotsys_imsg_recv_group(struct imsg *imsg, struct gotsys_group **group)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsg_sysconf_group igroup;
	char *name = NULL;
	size_t datalen;

	*group = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(igroup))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	memcpy(&igroup, imsg->data, sizeof(igroup));

	if (igroup.name_len <= 0 || igroup.name_len > _PW_NAME_LEN ||
	    sizeof(igroup) + igroup.name_len > datalen)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	name = strndup(imsg->data + sizeof(igroup), igroup.name_len);
	if (name == NULL)
		return got_error_from_errno("strdup");

	if (strlen(name) != igroup.name_len) {
		free(name);
		return got_error(GOT_ERR_PRIVSEP_LEN);
	}

	err = gotsys_conf_validate_name(name, "group");
	if (err) {
		free(name);
		return err;
	}
		
	err = gotsys_conf_new_group(group, name);
	free(name);
	return err;
}

const struct got_error *
gotsys_imsg_send_authorized_keys_user(struct gotsysd_imsgev *iev,
    const char *username, int imsg_type)
{
	const struct got_error *err;
	struct gotsysd_imsg_sysconf_authorized_keys_user iuser;
	struct ibuf *wbuf = NULL;
	size_t userlen;

	err = gotsys_conf_validate_name(username, "user");
	if (err)
		return err;

	userlen = strlen(username);

	iuser.name_len = strlen(username);

	wbuf = imsg_create(&iev->ibuf, imsg_type, 0, 0,
	    sizeof(iuser) + userlen);
	if (wbuf == NULL)
		return got_error_from_errno_fmt("imsg_create %d", imsg_type);

	if (imsg_add(wbuf, &iuser, sizeof(iuser)) == -1)
		return got_error_from_errno_fmt("imsg_add %d", imsg_type);
	if (imsg_add(wbuf, username, userlen) == -1)
		return got_error_from_errno_fmt("imsg_add %d", imsg_type);

	imsg_close(&iev->ibuf, wbuf);
	gotsysd_imsg_event_add(iev);

	return NULL;
}

const struct got_error *
gotsys_imsg_recv_authorized_keys_user(char **username, struct imsg *imsg)
{
	const struct got_error *err;
	struct gotsysd_imsg_sysconf_authorized_keys_user iuser;
	size_t datalen;

	*username = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(iuser))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&iuser, imsg->data, sizeof(iuser));

	if (iuser.name_len > _PW_NAME_LEN ||
	    datalen != sizeof(iuser) + iuser.name_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	*username = strndup(imsg->data + sizeof(iuser), iuser.name_len);
	if (*username == NULL)
		return got_error_from_errno("strndup");

	if (strlen(*username) != iuser.name_len) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		goto done;
	}

	err = gotsys_conf_validate_name(*username, "user");
done:
	if (err) {
		free(*username);
		*username = NULL;
	}

	return err;
}

const struct got_error *
gotsys_imsg_send_authorized_keys(struct gotsysd_imsgev *iev,
    struct gotsys_authorized_keys_list *keys, int imsg_type)
{
	const struct got_error *err;
	struct gotsys_authorized_key *k;
	size_t totlen, remain, mlen;
	const size_t maxmesg  = MAX_IMSGSIZE - IMSG_HEADER_SIZE;
	struct gotsysd_imsg_sysconf_authorized_key ikey;
	struct ibuf *wbuf = NULL;

	k = STAILQ_FIRST(keys);
	totlen = 0;
	while (k) {
		size_t typelen, datalen, commentlen, klen;

		typelen = strlen(k->keytype);
		if (typelen == 0) {
			return got_error_msg(GOT_ERR_AUTHORIZED_KEY,
			    "empty authorized key type");
		}
		if (typelen > GOTSYS_AUTHORIZED_KEY_MAXLEN) {
			return got_error_fmt(GOT_ERR_NO_SPACE,
			    "authorized key type too long: %s:", k->keytype);
		}
		datalen = strlen(k->key);
		if (datalen == 0) {
			return got_error_msg(GOT_ERR_AUTHORIZED_KEY,
			    "empty authorized key");
		}
		if (datalen > GOTSYS_AUTHORIZED_KEY_MAXLEN ||
		    typelen + datalen > GOTSYS_AUTHORIZED_KEY_MAXLEN) {
			return got_error_fmt(GOT_ERR_NO_SPACE,
			    "authorized key too long: %s:", k->key);
		}

		commentlen = strlen(k->comment);
		if (commentlen > GOTSYS_AUTHORIZED_KEY_MAXLEN) {
			return got_error_fmt(GOT_ERR_NO_SPACE,
			    "authorized key comment too long: %s:",
			    k->comment);
		}

		klen = typelen + datalen + commentlen;
		if (klen > GOTSYS_AUTHORIZED_KEY_MAXLEN) {
			return got_error_fmt(GOT_ERR_NO_SPACE,
			    "authorized key too long: %s:", k->key);
		}

		totlen += sizeof(ikey) + klen;
		k = STAILQ_NEXT(k, entry);
	}

	k = STAILQ_FIRST(keys);
	remain = totlen;
	mlen = 0;
	while (k && remain > 0) {
		size_t klen;

		ikey.keytype_len = strlen(k->keytype);
		ikey.keydata_len = strlen(k->key);
		ikey.comment_len = strlen(k->comment);

		klen = ikey.keytype_len + ikey.keydata_len + ikey.comment_len;

		if (wbuf != NULL && mlen + sizeof(ikey) + klen > maxmesg) {
			imsg_close(&iev->ibuf, wbuf);
			err = gotsysd_imsg_flush(&iev->ibuf);
			if (err)
				return err;
			wbuf = NULL;
			mlen = 0;
		}

		if (wbuf == NULL) {
			wbuf = imsg_create(&iev->ibuf, imsg_type, 0, 0,
			    MIN(remain, maxmesg));
			if (wbuf == NULL) {
				return got_error_from_errno_fmt(
				    "imsg_create %d", imsg_type);
			}
		}

		if (imsg_add(wbuf, &ikey, sizeof(ikey)) == -1)
			return got_error_from_errno_fmt("imsg_add %d",
			    imsg_type);
		if (imsg_add(wbuf, k->keytype, ikey.keytype_len) == -1)
			return got_error_from_errno_fmt("imsg_add %d",
			    imsg_type);
		if (imsg_add(wbuf, k->key, ikey.keydata_len) == -1)
			return got_error_from_errno_fmt("imsg_add %d",
			    imsg_type);
		if (imsg_add(wbuf, k->comment, ikey.comment_len) == -1)
			return got_error_from_errno_fmt("imsg_add %d",
			    imsg_type);

		remain -= sizeof(ikey) + klen;
		mlen += sizeof(ikey) + klen;
		k = STAILQ_NEXT(k, entry);
	}

	if (wbuf) {
		imsg_close(&iev->ibuf, wbuf);
		gotsysd_imsg_event_add(iev);
	}

	return NULL;
}

const struct got_error *
gotsys_imsg_recv_authorized_keys(struct imsg *imsg,
    struct gotsys_authorized_keys_list *keys)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsg_sysconf_authorized_key ikey;
	struct gotsys_authorized_key *key = NULL;
	char *keytype = NULL, *keydata = NULL, *comment = NULL;
	size_t datalen, offset, remain;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(ikey))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	remain = datalen;
	offset = 0;
	while (remain > 0) {
		size_t klen;

		if (remain < sizeof(ikey))
			return got_error(GOT_ERR_PRIVSEP_LEN);

		memcpy(&ikey, imsg->data + offset, sizeof(ikey));

		if (ikey.keytype_len == 0 ||
		    ikey.keydata_len == 0 ||
		    ikey.keytype_len > GOTSYS_AUTHORIZED_KEY_MAXLEN ||
		    ikey.keydata_len > GOTSYS_AUTHORIZED_KEY_MAXLEN ||
		    ikey.comment_len > GOTSYS_AUTHORIZED_KEY_MAXLEN)
			return got_error(GOT_ERR_PRIVSEP_LEN);

		klen = ikey.keytype_len + ikey.keydata_len + ikey.comment_len;
		if (klen > GOTSYS_AUTHORIZED_KEY_MAXLEN ||
		    sizeof(ikey) + klen > remain)
			return got_error(GOT_ERR_PRIVSEP_LEN);

		keytype = strndup(imsg->data + offset + sizeof(ikey),
		    ikey.keytype_len);
		if (keytype == NULL)
			return got_error_from_errno("strndup");
		if (strlen(keytype) != ikey.keytype_len) {
			free(keytype);
			return got_error(GOT_ERR_PRIVSEP_LEN);
		}

		keydata = strndup(imsg->data + offset + sizeof(ikey) +
		    ikey.keytype_len, ikey.keydata_len);
		if (keydata == NULL) {
			err = got_error_from_errno("strndup");
			goto done;
		}
		if (strlen(keydata) != ikey.keydata_len) {
			err = got_error(GOT_ERR_PRIVSEP_LEN);
			goto done;
		}

		if (ikey.comment_len > 0) {
			comment = strndup(imsg->data + offset + sizeof(ikey) +
			    ikey.keytype_len + ikey.keydata_len,
			    ikey.comment_len);
			if (comment == NULL) {
				err = got_error_from_errno("strndup");
				goto done;
			}
			if (strlen(comment) != ikey.comment_len) {
				err = got_error(GOT_ERR_PRIVSEP_LEN);
				goto done;
			}
		}
		err = gotsys_conf_new_authorized_key(&key, keytype,
		    keydata, comment);
		if (err)
			goto done;
		free(keytype);
		free(keydata);
		free(comment);
		keytype = NULL;
		keydata = NULL;
		comment = NULL;

		STAILQ_INSERT_TAIL(keys, key, entry);
		key = NULL;
		offset += sizeof(ikey) + klen;
		remain -= sizeof(ikey) + klen;
	}

done:
	free(keytype);
	free(keydata);
	free(comment);
	gotsys_authorized_key_free(key);
	return err;
}

static const struct got_error *
send_access_rule(struct gotsysd_imsgev *iev,
    struct gotsys_access_rule *rule)
{
	struct gotsysd_imsg_sysconf_access_rule irule;
	struct ibuf *wbuf = NULL;

	switch (rule->access) {
	case GOTSYS_ACCESS_DENIED:
		irule.access = GOTSYSD_IMSG_ACCESS_DENIED;
		break;
	case GOTSYS_ACCESS_PERMITTED:
		irule.access = GOTSYSD_IMSG_ACCESS_PERMITTED;
		break;
	default:
		return got_error_fmt(GOT_ERR_NOT_IMPL,
		    "unknown access %d", rule->access);
	}
	irule.authorization = rule->authorization;
	irule.identifier_len = strlen(rule->identifier);

	wbuf = imsg_create(&iev->ibuf, GOTSYSD_IMSG_SYSCONF_ACCESS_RULE,
	    0, 0, sizeof(irule) + irule.identifier_len);
	if (wbuf == NULL)
		return got_error_from_errno("imsg_create SYSCONF_ACCESS_RULE");

	if (imsg_add(wbuf, &irule, sizeof(irule)) == -1)
		return got_error_from_errno("imsg_add SYSCONF_ACCESS_FULE");
	if (imsg_add(wbuf, rule->identifier, irule.identifier_len) == -1)
		return got_error_from_errno("imsg_add SYSCONF_ACCESS_FULE");

	imsg_close(&iev->ibuf, wbuf);
	return gotsysd_imsg_flush(&iev->ibuf);
}

static const struct got_error *
send_repo(struct gotsysd_imsgev *iev, struct gotsys_repo *repo)
{
	const struct got_error *err;
	struct gotsysd_imsg_sysconf_repo irepo;
	struct gotsys_access_rule *rule;
	struct ibuf *wbuf = NULL;

	irepo.name_len = strlen(repo->name);

	wbuf = imsg_create(&iev->ibuf, GOTSYSD_IMSG_SYSCONF_REPO,
	    0, 0, sizeof(irepo) + irepo.name_len);
	if (wbuf == NULL)
		return got_error_from_errno("imsg_create SYSCONF_REPO");

	if (imsg_add(wbuf, &irepo, sizeof(irepo)) == -1)
		return got_error_from_errno("imsg_add SYSCONF_REPO");
	if (imsg_add(wbuf, repo->name, irepo.name_len) == -1)
		return got_error_from_errno("imsg_add SYSCONF_REPO");

	imsg_close(&iev->ibuf, wbuf);
	err = gotsysd_imsg_flush(&iev->ibuf);
	if (err)
		return err;

	STAILQ_FOREACH(rule, &repo->access_rules, entry) {
		err = send_access_rule(iev, rule);
		if (err)
			return err;
	}

	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_ACCESS_RULES_DONE, 0, -1, NULL, 0) == -1) {
		return got_error_from_errno("gotsysd_imsg_compose_event");
	}

	/* TODO: send protected tags and branches */

	/* TODO: send notification config */

	return NULL;
}

const struct got_error *
gotsys_imsg_send_repositories(struct gotsysd_imsgev *iev,
    struct gotsys_repolist *repos)
{
	const struct got_error *err = NULL;
	struct gotsys_repo *repo;

	TAILQ_FOREACH(repo, repos, entry) {
		err = send_repo(iev, repo);
		if (err)
			return err;
	}

	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_REPOS_DONE, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("gotsysd_imsg_compose_event");

	return NULL;
}

const struct got_error *
gotsys_imsg_recv_repository(struct gotsys_repo **repo, struct imsg *imsg)
{
	const struct got_error *err;
	struct gotsysd_imsg_sysconf_repo irepo;
	size_t datalen;
	char *name = NULL;

	*repo = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(irepo))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	
	memcpy(&irepo, imsg->data, sizeof(irepo));
	if (datalen != sizeof(irepo) + irepo.name_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	name = strndup(imsg->data + sizeof(irepo), irepo.name_len);
	if (name == NULL)
		return got_error_from_errno("strndup");
	if (strlen(name) != irepo.name_len) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		free(name);
		return err;
	}

	err = gotsys_conf_new_repo(repo, name);
	free(name);
	return err;
}

const struct got_error *
gotsys_imsg_recv_access_rule(struct gotsys_access_rule **rule,
    struct imsg *imsg, struct gotsys_userlist *users,
    struct gotsys_grouplist *groups)
{
	const struct got_error *err;
	struct gotsysd_imsg_sysconf_access_rule irule;
	enum gotsys_access access;
	size_t datalen;
	char *identifier = NULL;

	*rule = NULL;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(irule))
		return got_error(GOT_ERR_PRIVSEP_LEN);

	memcpy(&irule, imsg->data, sizeof(irule));
	if (datalen != sizeof(irule) + irule.identifier_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);
	if (irule.identifier_len == 0) {
		return got_error_msg(GOT_ERR_PRIVSEP_LEN,
		    "empty access rule identifier");
	}
	if (irule.identifier_len > _PW_NAME_LEN) {
		return got_error_msg(GOT_ERR_PRIVSEP_LEN,
		    "access rule identifier too long");
	}

	switch (irule.access) {
	case GOTSYSD_IMSG_ACCESS_PERMITTED:
		if (irule.authorization == 0) {
			return got_error_msg(GOT_ERR_PRIVSEP_MSG,
			    "permit access rule without read or write "
			    "authorization");
		}
		access = GOTSYS_ACCESS_PERMITTED;
		break;
	case GOTSYSD_IMSG_ACCESS_DENIED:
		if (irule.authorization != 0) {
			return got_error_msg(GOT_ERR_PRIVSEP_MSG,
			    "deny access rule with read or write "
			    "authorization");
		}
		access = GOTSYS_ACCESS_DENIED;
		break;
	default:
		return got_error_msg(GOT_ERR_PRIVSEP_MSG,
		    "invalid access rule");
	}

	if (irule.authorization & ~(GOTSYS_AUTH_READ | GOTSYS_AUTH_WRITE)) {
		return got_error_msg(GOT_ERR_PRIVSEP_MSG,
		    "invalid access rule authorization flags");
	}
	
	identifier = strndup(imsg->data + sizeof(irule), irule.identifier_len);
	if (identifier == NULL)
		return got_error_from_errno("strndup");
	if (strlen(identifier) != irule.identifier_len) {
		err = got_error(GOT_ERR_PRIVSEP_LEN);
		free(identifier);
		return err;
	}

	err = gotsys_conf_new_access_rule(rule, access, irule.authorization,
	    identifier, users, groups);
	free(identifier);
	return err;
}
