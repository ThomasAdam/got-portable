
/*
 * Copyright (c) 2020, 2025 Stefan Sperling <stsp@openbsd.org>
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
#include <sys/stat.h>

#include <err.h>
#include <event.h>
#include <imsg.h>
#include <limits.h>
#include <sha1.h>
#include <sha2.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "got_error.h"
#include "got_path.h"
#include "got_opentemp.h"
#include "got_object.h"
#include "got_reference.h"

#include "gotsysd.h"
#include "gotsys.h"

static struct gotsys_conf gotsysconf;
static struct gotsys_userlist *users_cur;
static struct gotsys_repo *repo_cur;
static struct got_pathlist_head *protected_refs_cur;
static size_t nprotected_refs_needed;
static size_t nprotected_refs_received;
static int gotd_conf_tmpfd = -1;
static char *gotd_conf_tmppath;

enum writeconf_state {
	WRITECONF_STATE_EXPECT_USERS,
	WRITECONF_STATE_EXPECT_GROUPS,
	WRITECONF_STATE_EXPECT_REPOS,
	WRITECONF_STATE_WRITE_CONF,
	WRITECONF_STATE_DONE
};

static enum writeconf_state writeconf_state = WRITECONF_STATE_EXPECT_USERS;

static void
sighdlr(int sig, short event, void *arg)
{
	/*
	 * Normal signal handler rules don't apply because libevent
	 * decouples for us.
	 */

	switch (sig) {
	case SIGHUP:
		break;
	case SIGUSR1:
		break;
	case SIGTERM:
	case SIGINT:
		event_loopexit(NULL);
		break;
	default:
		break;
	}
}

static const struct got_error *
send_done(struct gotsysd_imsgev *iev)
{
	if (gotsysd_imsg_compose_event(iev,
	    GOTSYSD_IMSG_SYSCONF_WRITE_CONF_DONE,
	    0, -1, NULL, 0) == -1) {
		return got_error_from_errno("imsg_compose "
		    "SYSCONF_WRITE_CONF_DONE");
	}

	return NULL;
}

static const struct got_error *
write_access_rules(struct gotsys_access_rule_list *rules)
{
	struct gotsys_access_rule *rule;

	STAILQ_FOREACH(rule, rules, entry) {
		const char *access, *authorization;
		int ret;

		switch (rule->access) {
		case GOTSYS_ACCESS_DENIED:
			access = "deny";
			break;
		case GOTSYS_ACCESS_PERMITTED:
			access = "permit";
			break;
		default:
			return got_error_fmt(GOT_ERR_PARSE_CONFIG,
			    "access rule with unknown access flag %d",
			    rule->access);
		}

		if (rule->authorization & GOTSYS_AUTH_WRITE)
			authorization = "rw";
		else if (rule->authorization & GOTSYS_AUTH_READ)
			authorization = "ro";
		else
			return got_error_fmt(GOT_ERR_PARSE_CONFIG,
			    "unknown access rule authorization flags 0x%x",
			    rule->authorization);

		ret = dprintf(gotd_conf_tmpfd, "\t%s %s %s\n",
		    access, authorization, rule->identifier);
		if (ret == -1)
			return got_error_from_errno2("dprintf",
			    gotd_conf_tmppath);
		if (ret != 3 + strlen(access) + strlen(authorization) +
		    strlen(rule->identifier) + 1) {
			return got_error_fmt(GOT_ERR_IO,
			    "short write to %s", gotd_conf_tmppath);
		}
	}

	return NULL;
}

static const struct got_error *
refname_is_valid(const char *refname)
{
	if (strncmp(refname, "refs/", 5) != 0) {
		return got_error_fmt( GOT_ERR_BAD_REF_NAME,
		    "reference name must begin with \"refs/\": %s", refname);
	}

	if (!got_ref_name_is_valid(refname))
		return got_error_path(refname, GOT_ERR_BAD_REF_NAME);

	return NULL;
}

static const struct got_error *
write_protected_refs(struct gotsys_repo *repo)
{
	const struct got_error *err = NULL;
	struct got_pathlist_entry *pe;
	int ret;
	const char *opening = "protect {";
	const char *closing = "}";
	char *namespace = NULL;

	if (RB_EMPTY(&repo->protected_tag_namespaces) &&
	    RB_EMPTY(&repo->protected_branch_namespaces) &&
	    RB_EMPTY(&repo->protected_branches))
		return NULL;

	ret = dprintf(gotd_conf_tmpfd, "\t%s\n", opening);
	if (ret == -1)
		return got_error_from_errno2("dprintf", gotd_conf_tmppath);
	if (ret != 2 + strlen(opening))
		return got_error_fmt(GOT_ERR_IO, "short write to %s",
		    gotd_conf_tmppath);

	RB_FOREACH(pe, got_pathlist_head, &repo->protected_tag_namespaces) {
		namespace = strdup(pe->path);
		if (namespace == NULL)
			return got_error_from_errno("strdup");

		got_path_strip_trailing_slashes(namespace);
		err = refname_is_valid(namespace);
		if (err)
			goto done;

		ret = dprintf(gotd_conf_tmpfd, "\t\ttag namespace \"%s\"\n",
		    namespace);
		if (ret == -1) {
			err = got_error_from_errno2("dprintf",
			    gotd_conf_tmppath);
			goto done;
		}
		if (ret != 19 + strlen(namespace)) {
			err = got_error_fmt(GOT_ERR_IO, "short write to %s",
			    gotd_conf_tmppath);
			goto done;
		}
		free(namespace);
		namespace = NULL;
	}

	RB_FOREACH(pe, got_pathlist_head, &repo->protected_branch_namespaces) {
		namespace = strdup(pe->path);
		if (namespace == NULL)
			return got_error_from_errno("strdup");

		got_path_strip_trailing_slashes(namespace);
		err = refname_is_valid(namespace);
		if (err)
			goto done;

		ret = dprintf(gotd_conf_tmpfd, "\t\tbranch namespace \"%s\"\n",
		    namespace);
		if (ret == -1) {
			err = got_error_from_errno2("dprintf",
			    gotd_conf_tmppath);
			goto done;
		}
		if (ret != 22 + strlen(namespace)) {
			err = got_error_fmt(GOT_ERR_IO, "short write to %s",
			    gotd_conf_tmppath);
			goto done;
		}
		free(namespace);
		namespace = NULL;
	}

	RB_FOREACH(pe, got_pathlist_head, &repo->protected_branches) {
		err = refname_is_valid(pe->path);
		if (err)
			return err;
		ret = dprintf(gotd_conf_tmpfd, "\t\tbranch \"%s\"\n", pe->path);
		if (ret == -1) {
			return got_error_from_errno2("dprintf",
			    gotd_conf_tmppath);
		}
		if (ret != 12 + strlen(pe->path))
			return got_error_fmt(GOT_ERR_IO, "short write to %s",
			    gotd_conf_tmppath);
	}

	ret = dprintf(gotd_conf_tmpfd, "\t%s\n", closing);
	if (ret == -1)
		return got_error_from_errno2("dprintf", gotd_conf_tmppath);
	if (ret != 2 + strlen(closing))
		return got_error_fmt(GOT_ERR_IO, "short write to %s",
		    gotd_conf_tmppath);
done:
	free(namespace);
	return NULL;
}

static const struct got_error *
write_gotd_conf(void)
{
	const struct got_error *err = NULL;
	struct gotsys_repo *repo;
	int ret;
	char repo_path[_POSIX_PATH_MAX];
	struct timespec now;

	if (ftruncate(gotd_conf_tmpfd, 0) == -1)
		return got_error_from_errno("ftruncate");

	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1)
		return got_error_from_errno("clock_gettime");

	/* TODO: show gotsys.git commit hash */
	ret = dprintf(gotd_conf_tmpfd, "# generated by gotsysd, do not edit\n");
	if (ret == -1)
		return got_error_from_errno2("dprintf",
		    gotd_conf_tmppath);
	if (ret != 35 + 1) {
		return got_error_fmt(GOT_ERR_IO,
		    "short write to %s", gotd_conf_tmppath);
	}

	TAILQ_FOREACH(repo, &gotsysconf.repos, entry) {
		char *name = NULL;
		size_t namelen;

		ret = dprintf(gotd_conf_tmpfd, "repository \"%s\" {\n",
		    repo->name);
		if (ret == -1)
			return got_error_from_errno2("dprintf",
			    gotd_conf_tmppath);
		if (ret != 15 + strlen(repo->name) + 1) {
			return got_error_fmt(GOT_ERR_IO,
			    "short write to %s", gotd_conf_tmppath);
		}

		namelen = strlen(repo->name);
		if (namelen < 4 ||
		    strcmp(&repo->name[namelen - 4], ".git") != 0) {
			if (asprintf(&name, "%s.git", repo->name) == -1)
				return got_error_from_errno("asprintf");
		} else {
			name = strdup(repo->name);
			if (name == NULL)
				return got_error_from_errno("strdup");
		}
		/* TODO: Honour repository path set in gotsysd.conf. */
		ret = snprintf(repo_path, sizeof(repo_path),
		    "%s/%s", GOTSYSD_REPOSITORIES_PATH, name);
		free(name);
		name = NULL;
		if (ret == -1)
			return got_error_from_errno("snprintf");
		if ((size_t)ret >= sizeof(repo_path)) {
			return got_error_msg(GOT_ERR_NO_SPACE,
			    "repository path too long");
		}

		ret = dprintf(gotd_conf_tmpfd, "\tpath \"%s\"\n", repo_path);
		if (ret == -1)
			return got_error_from_errno2("dprintf",
			    gotd_conf_tmppath);
		if (ret != 8 + strlen(repo_path) + 1) {
			return got_error_fmt(GOT_ERR_IO,
			    "short write to %s", gotd_conf_tmppath);
		}

		err = write_access_rules(&repo->access_rules);
		if (err)
			return err;

		err = write_protected_refs(repo);
		if (err)
			return err;

		ret = dprintf(gotd_conf_tmpfd, "}\n");
		if (ret == -1)
			return got_error_from_errno2("dprintf",
			    gotd_conf_tmppath);
		if (ret != 2) {
			return got_error_fmt(GOT_ERR_IO,
			    "short write to %s", gotd_conf_tmppath);
		}
	}

	if (fchmod(gotd_conf_tmpfd, 0644) == -1) {
		return got_error_from_errno_fmt("chmod 0644 %s",
		    gotd_conf_tmppath);
	}
		
	if (rename(gotd_conf_tmppath, GOTD_CONF_PATH) == -1) {
		return got_error_from_errno_fmt("rename %s to %s",
		    gotd_conf_tmppath, GOTD_CONF_PATH);
	}

	free(gotd_conf_tmppath);
	gotd_conf_tmppath = NULL;
	return NULL;
}

static void
dispatch_event(int fd, short event, void *arg)
{
	const struct got_error *err = NULL;
	struct gotsysd_imsgev *iev = arg;
	struct imsgbuf *ibuf = &iev->ibuf;
	struct imsg imsg;
	ssize_t n;
	size_t npaths;
	int shut = 0;
	static int flush_and_exit;

	if (event & EV_READ) {
		if ((n = imsgbuf_read(ibuf)) == -1) {
			warn("imsgbuf_read error");
			goto fatal;
		}
		if (n == 0)	/* Connection closed. */
			shut = 1;
	}

	if (event & EV_WRITE) {
		err = gotsysd_imsg_flush(ibuf);
		if (err) {
			warn("%s", err->msg);
			goto fatal;
		}

		if (flush_and_exit) {
			event_del(&iev->ev);
			event_loopexit(NULL);
			return;
		}
	}

	for (;;) {
		if ((n = imsg_get(ibuf, &imsg)) == -1) {
			warn("%s: imsg_get", __func__);
			goto fatal;
		}
		if (n == 0)	/* No more messages. */
			break;

		switch (imsg.hdr.type) {
		case GOTSYSD_IMSG_SYSCONF_WRITE_CONF_USERS:
			if (writeconf_state != WRITECONF_STATE_EXPECT_USERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			err = gotsys_imsg_recv_users(&imsg, &gotsysconf.users);
			break;
		case GOTSYSD_IMSG_SYSCONF_WRITE_CONF_USERS_DONE:
			if (writeconf_state != WRITECONF_STATE_EXPECT_USERS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			writeconf_state = WRITECONF_STATE_EXPECT_GROUPS;
			break;
		case GOTSYSD_IMSG_SYSCONF_WRITE_CONF_GROUP: {
			struct gotsys_group *group;

			if (writeconf_state != WRITECONF_STATE_EXPECT_GROUPS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			err = gotsys_imsg_recv_group(&imsg, &group);
			if (err)
				break;
			STAILQ_INSERT_TAIL(&gotsysconf.groups, group, entry);
			users_cur = &group->members;
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_WRITE_CONF_GROUP_MEMBERS:
			if (users_cur == NULL ||
			    writeconf_state != WRITECONF_STATE_EXPECT_GROUPS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			err = gotsys_imsg_recv_users(&imsg, users_cur);
			break;
		case GOTSYSD_IMSG_SYSCONF_WRITE_CONF_GROUP_MEMBERS_DONE:
			if (users_cur == NULL ||
			    writeconf_state != WRITECONF_STATE_EXPECT_GROUPS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			users_cur = NULL;
			break;
		case GOTSYSD_IMSG_SYSCONF_WRITE_CONF_GROUPS_DONE:
			if (writeconf_state != WRITECONF_STATE_EXPECT_GROUPS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			writeconf_state = WRITECONF_STATE_EXPECT_REPOS;
			break;
		case GOTSYSD_IMSG_SYSCONF_REPO: {
			struct gotsys_repo *repo;

			if (writeconf_state != WRITECONF_STATE_EXPECT_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			err = gotsys_imsg_recv_repository(&repo, &imsg);
			if (err)
				break;
			TAILQ_INSERT_TAIL(&gotsysconf.repos, repo, entry);
			repo_cur = repo;
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_ACCESS_RULE: {
			struct gotsys_access_rule_list *rules;
			struct gotsys_access_rule *rule;

			if (repo_cur == NULL ||
			    writeconf_state != WRITECONF_STATE_EXPECT_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			err = gotsys_imsg_recv_access_rule(&rule, &imsg,
			    &gotsysconf.users, &gotsysconf.groups);
			if (err)
				break;
			rules = &repo_cur->access_rules;
			STAILQ_INSERT_TAIL(rules, rule, entry);
			break;
		}
		case GOTSYSD_IMSG_SYSCONF_ACCESS_RULES_DONE:
			if (repo_cur == NULL ||
			    writeconf_state != WRITECONF_STATE_EXPECT_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			break;
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_TAG_NAMESPACES:
			if (repo_cur == NULL ||
			    writeconf_state != WRITECONF_STATE_EXPECT_REPOS ||
			    protected_refs_cur != NULL ||
			    nprotected_refs_needed != 0) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = gotsys_imsg_recv_pathlist(&npaths, &imsg);
			if (err)
				break;
			protected_refs_cur =
			    &repo_cur->protected_tag_namespaces;
			nprotected_refs_needed = npaths;
			nprotected_refs_received = 0;
			break;
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCH_NAMESPACES:
			if (repo_cur == NULL ||
			    writeconf_state != WRITECONF_STATE_EXPECT_REPOS ||
			    protected_refs_cur != NULL ||
			    nprotected_refs_needed != 0) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = gotsys_imsg_recv_pathlist(&npaths, &imsg);
			if (err)
				break;
			protected_refs_cur =
			    &repo_cur->protected_branch_namespaces;
			nprotected_refs_needed = npaths;
			nprotected_refs_received = 0;
			break;
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCHES:
			if (repo_cur == NULL ||
			    writeconf_state != WRITECONF_STATE_EXPECT_REPOS ||
			    protected_refs_cur != NULL ||
			    nprotected_refs_needed != 0) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			err = gotsys_imsg_recv_pathlist(&npaths, &imsg);
			if (err)
				break;
			protected_refs_cur =
			    &repo_cur->protected_branches;
			nprotected_refs_needed = npaths;
			nprotected_refs_received = 0;
			break;
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_TAG_NAMESPACES_ELEM:
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCH_NAMESPACES_ELEM:
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_BRANCHES_ELEM:
			if (protected_refs_cur == NULL ||
			    writeconf_state != WRITECONF_STATE_EXPECT_REPOS ||
			    nprotected_refs_needed == 0 ||
			    nprotected_refs_received >=
			    nprotected_refs_needed) {
				err = got_error(GOT_ERR_PRIVSEP_MSG);
				break;
			}
			/* TODO: validate refname validity */
			err = gotsys_imsg_recv_pathlist_elem(&imsg,
			    protected_refs_cur);
			if (err)
				break;
			if (++nprotected_refs_received >=
			    nprotected_refs_needed) {
				protected_refs_cur = NULL;
				nprotected_refs_needed = 0;
			}
			break;
		case GOTSYSD_IMSG_SYSCONF_PROTECTED_REFS_DONE:
			if (repo_cur == NULL ||
			    nprotected_refs_needed != 0 ||
			    writeconf_state != WRITECONF_STATE_EXPECT_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			repo_cur = NULL;
			break;
		case GOTSYSD_IMSG_SYSCONF_REPOS_DONE:
			if (writeconf_state != WRITECONF_STATE_EXPECT_REPOS) {
				err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
				    "received unexpected imsg %d while in "
				    "state %d\n", imsg.hdr.type,
				    writeconf_state);
				break;
			}
			repo_cur = NULL;
			writeconf_state = WRITECONF_STATE_WRITE_CONF;
			err = write_gotd_conf();
			if (err)
				break;
			writeconf_state = WRITECONF_STATE_DONE;
			err = send_done(iev);
			flush_and_exit = 1;
			break;
		default:
			err = got_error_fmt(GOT_ERR_PRIVSEP_MSG,
			    "unexpected imsg %d", imsg.hdr.type);
			break;
		}

		if (err) {
			warnx("imsg %d: %s", imsg.hdr.type, err->msg);
			gotsysd_imsg_send_error(&iev->ibuf, 0, 0, err);
			flush_and_exit = 1;
		}

		imsg_free(&imsg);
	}

	if (!shut) {
		gotsysd_imsg_event_add(iev);
	} else {
fatal:
		/* This pipe is dead. Remove its event handler */
		event_del(&iev->ev);
		event_loopexit(NULL);
	}
}

int
main(int argc, char *argv[])
{
	const struct got_error *err = NULL;
	struct gotsysd_imsgev iev;
	struct event evsigint, evsigterm, evsighup, evsigusr1;
#if 0
	static int attached;

	while (!attached)
		sleep(1);
#endif
	gotsys_conf_init(&gotsysconf);

	event_init();

	signal_set(&evsigint, SIGINT, sighdlr, NULL);
	signal_set(&evsigterm, SIGTERM, sighdlr, NULL);
	signal_set(&evsighup, SIGHUP, sighdlr, NULL);
	signal_set(&evsigusr1, SIGUSR1, sighdlr, NULL);
	signal(SIGPIPE, SIG_IGN);

	signal_add(&evsigint, NULL);
	signal_add(&evsigterm, NULL);
	signal_add(&evsighup, NULL);
	signal_add(&evsigusr1, NULL);

	if (imsgbuf_init(&iev.ibuf, GOTSYSD_FILENO_MSG_PIPE) == -1) {
		warn("imsgbuf_init");
		return 1;
	}

	/* TODO: make gotd.conf path configurable -- pass via argv[1] */
	err = got_opentemp_named_fd(&gotd_conf_tmppath, &gotd_conf_tmpfd,
	    GOTD_CONF_PATH, "");
	if (err)
		goto done;
#ifndef PROFILE
	if (pledge("stdio rpath wpath cpath fattr chown unveil", NULL) == -1) {
		err = got_error_from_errno("pledge");
		goto done;
	}
#endif
	if (unveil(gotd_conf_tmppath, "rwc") == -1) {
		err = got_error_from_errno2("unveil rwc", gotd_conf_tmppath);
		goto done;
	}

	if (unveil(GOTD_CONF_PATH, "rwc") == -1) {
		err = got_error_from_errno2("unveil rwc", GOTD_CONF_PATH);
		goto done;
	}

	if (unveil(NULL, NULL) == -1) {
		err = got_error_from_errno("unveil");
		goto done;
	}

	iev.handler = dispatch_event;
	iev.events = EV_READ;
	iev.handler_arg = NULL;
	event_set(&iev.ev, iev.ibuf.fd, EV_READ, dispatch_event, &iev);
	if (gotsysd_imsg_compose_event(&iev, GOTSYSD_IMSG_PROG_READY, 0,
	    -1, NULL, 0) == -1) {
		err = got_error_from_errno("gotsysd_imsg_compose_event");
		goto done;
	}

	event_dispatch();
done:
	gotsys_conf_clear(&gotsysconf);
	if (gotd_conf_tmppath && unlink(gotd_conf_tmppath) == -1 && err == NULL)
		err = got_error_from_errno2("unlink", gotd_conf_tmppath);
	free(gotd_conf_tmppath);
	if (close(GOTSYSD_FILENO_MSG_PIPE) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (gotd_conf_tmpfd != -1 && close(gotd_conf_tmpfd) == -1 &&
	    err == NULL)
		err = got_error_from_errno("close");
	if (err)
		gotsysd_imsg_send_error(&iev.ibuf, 0, 0, err);
	imsgbuf_clear(&iev.ibuf);
	return err ? 1 : 0;
}
