/*
 * Copyright (c) 2022 Stefan Sperling <stsp@openbsd.org>
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
#include <sys/socket.h>
#include <sys/un.h>

#include <err.h>
#include <event.h>
#include <imsg.h>
#include <limits.h>
#include <locale.h>
#include <sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include "got_error.h"
#include "got_version.h"

#include "got_lib_gitproto.h"

#include "gotd.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

#define GOTCTL_CMD_INFO "info"
#define GOTCTL_CMD_STOP "stop"

struct gotctl_cmd {
	const char	*cmd_name;
	const struct got_error *(*cmd_main)(int, char *[], int);
	void		(*cmd_usage)(void);
};

__dead static void	usage(int, int);

__dead static void	usage_info(void);
__dead static void	usage_stop(void);

static const struct got_error*		cmd_info(int, char *[], int);
static const struct got_error*		cmd_stop(int, char *[], int);

static const struct gotctl_cmd gotctl_commands[] = {
	{ "info",	cmd_info,	usage_info },
	{ "stop",	cmd_stop,	usage_stop },
};

__dead static void
usage_info(void)
{
	fprintf(stderr, "usage: %s info\n", getprogname());
	exit(1);
}

static const struct got_error *
show_info(struct imsg *imsg)
{
	struct gotd_imsg_info info;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(info))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&info, imsg->data, sizeof(info));

	printf("gotd PID: %d\n", info.pid);
	printf("verbosity: %d\n", info.verbosity);
	printf("number of repositories: %d\n", info.nrepos);
	printf("number of connected clients: %d\n", info.nclients);
	return NULL;
}

static const struct got_error *
show_repo_info(struct imsg *imsg)
{
	struct gotd_imsg_info_repo info;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(info))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&info, imsg->data, sizeof(info));

	printf("repository \"%s\", path %s\n", info.repo_name, info.repo_path);
	return NULL;
}

static const char *
get_state_name(enum gotd_client_state state)
{
	static char unknown_state[64];

	switch (state) {
	case GOTD_STATE_EXPECT_LIST_REFS:
		return "list-refs";
	case GOTD_STATE_EXPECT_CAPABILITIES:
		return "expect-capabilities";
	case GOTD_STATE_EXPECT_WANT:
		return "expect-want";
	case GOTD_STATE_EXPECT_REF_UPDATE:
		return "expect-ref-update";
	case GOTD_STATE_EXPECT_MORE_REF_UPDATES:
		return "expect-more-ref-updates";
	case GOTD_STATE_EXPECT_HAVE:
		return "expect-have";
	case GOTD_STATE_EXPECT_PACKFILE:
		return "expect-packfile";
	case GOTD_STATE_EXPECT_DONE:
		return "expect-done";
	case GOTD_STATE_DONE:
		return "done";
	}

	snprintf(unknown_state, sizeof(unknown_state),
	    "unknown state %d", state);
	return unknown_state;
}

static const struct got_error *
show_client_info(struct imsg *imsg)
{
	struct gotd_imsg_info_client info;
	size_t datalen;

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen != sizeof(info))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&info, imsg->data, sizeof(info));

	printf("client UID %d, GID %d, protocol state '%s', ",
	    info.euid, info.egid, get_state_name(info.state));
	if (info.is_writing)
		printf("writing to %s\n", info.repo_name);
	else
		printf("reading from %s\n", info.repo_name);

	return NULL;
}

static const struct got_error *
show_capability(struct imsg *imsg)
{
	struct gotd_imsg_capability icapa;
	size_t datalen;
	char *key, *value = NULL;

	memset(&icapa, 0, sizeof(icapa));

	datalen = imsg->hdr.len - IMSG_HEADER_SIZE;
	if (datalen < sizeof(icapa))
		return got_error(GOT_ERR_PRIVSEP_LEN);
	memcpy(&icapa, imsg->data, sizeof(icapa));

	if (datalen != sizeof(icapa) + icapa.key_len + icapa.value_len)
		return got_error(GOT_ERR_PRIVSEP_LEN);

	key = malloc(icapa.key_len + 1);
	if (key == NULL)
		return got_error_from_errno("malloc");
	if (icapa.value_len > 0) {
		value = malloc(icapa.value_len + 1);
		if (value == NULL) {
			free(key);
			return got_error_from_errno("malloc");
		}
	}

	memcpy(key, imsg->data + sizeof(icapa), icapa.key_len);
	key[icapa.key_len] = '\0';
	if (value) {
		memcpy(value, imsg->data + sizeof(icapa) + icapa.key_len,
		    icapa.value_len);
		value[icapa.value_len] = '\0';
	}

	if (strcmp(key, GOT_CAPA_AGENT) == 0)
		printf("  client user agent: %s\n", value);
	else if (value)
		printf("  client supports %s=%s\n", key, value);
	else
		printf("  client supports %s\n", key);

	free(key);
	free(value);
	return NULL;
}

static const struct got_error *
cmd_info(int argc, char *argv[], int gotd_sock)
{
	const struct got_error *err;
	struct imsgbuf ibuf;
	struct imsg imsg;

	imsg_init(&ibuf, gotd_sock);

	if (imsg_compose(&ibuf, GOTD_IMSG_INFO, 0, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose INFO");

	err = gotd_imsg_flush(&ibuf);
	while (err == NULL) {
		err = gotd_imsg_poll_recv(&imsg, &ibuf, 0);
		if (err) {
			if (err->code == GOT_ERR_EOF)
				err = NULL;
			break;
		}
		
		switch (imsg.hdr.type) {
		case GOTD_IMSG_ERROR:
			err = gotd_imsg_recv_error(NULL, &imsg);
			break;
		case GOTD_IMSG_INFO:
			err = show_info(&imsg);
			break;
		case GOTD_IMSG_INFO_REPO:
			err = show_repo_info(&imsg);
			break;
		case GOTD_IMSG_INFO_CLIENT:
			err = show_client_info(&imsg);
			break;
		case GOTD_IMSG_CAPABILITY:
			err = show_capability(&imsg);
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
	}

	imsg_clear(&ibuf);
	return err;
}

__dead static void
usage_stop(void)
{
	fprintf(stderr, "usage: %s stop\n", getprogname());
	exit(1);
}

static const struct got_error *
cmd_stop(int argc, char *argv[], int gotd_sock)
{
	const struct got_error *err;
	struct imsgbuf ibuf;
	struct imsg imsg;

	imsg_init(&ibuf, gotd_sock);

	if (imsg_compose(&ibuf, GOTD_IMSG_STOP, 0, 0, -1, NULL, 0) == -1)
		return got_error_from_errno("imsg_compose STOP");

	err = gotd_imsg_flush(&ibuf);
	while (err == NULL) {
		err = gotd_imsg_poll_recv(&imsg, &ibuf, 0);
		if (err) {
			if (err->code == GOT_ERR_EOF)
				err = NULL;
			break;
		}
		
		switch (imsg.hdr.type) {
		case GOTD_IMSG_ERROR:
			err = gotd_imsg_recv_error(NULL, &imsg);
			break;
		default:
			err = got_error(GOT_ERR_PRIVSEP_MSG);
			break;
		}

		imsg_free(&imsg);
	}

	imsg_clear(&ibuf);
	return err;
}

static void
list_commands(FILE *fp)
{
	size_t i;

	fprintf(fp, "commands:");
	for (i = 0; i < nitems(gotctl_commands); i++) {
		const struct gotctl_cmd *cmd = &gotctl_commands[i];
		fprintf(fp, " %s", cmd->cmd_name);
	}
	fputc('\n', fp);
}

__dead static void
usage(int hflag, int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;

	fprintf(fp, "usage: %s [-hV] [-f path] command [arg ...]\n",
	    getprogname());
	if (hflag)
		list_commands(fp);
	exit(status);
}

static const struct got_error *
apply_unveil(const char *unix_socket_path)
{
#ifdef PROFILE
	if (unveil("gmon.out", "rwc") != 0)
		return got_error_from_errno2("unveil", "gmon.out");
#endif
	if (unveil(unix_socket_path, "w") != 0)
		return got_error_from_errno2("unveil", unix_socket_path);

	if (unveil(NULL, NULL) != 0)
		return got_error_from_errno("unveil");

	return NULL;
}

static int
connect_gotd(const char *socket_path)
{
	const struct got_error *error = NULL;
	int gotd_sock = -1;
	struct sockaddr_un sun;

	error = apply_unveil(socket_path);
	if (error)
		errx(1, "%s", error->msg);

#ifndef PROFILE
	if (pledge("stdio unix", NULL) == -1)
		err(1, "pledge");
#endif
	if ((gotd_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		err(1, "socket");

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	if (strlcpy(sun.sun_path, socket_path, sizeof(sun.sun_path)) >=
	    sizeof(sun.sun_path))
		errx(1, "gotd socket path too long");
	if (connect(gotd_sock, (struct sockaddr *)&sun, sizeof(sun)) == -1)
		err(1, "connect: %s", socket_path);

#ifndef PROFILE
	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");
#endif

	return gotd_sock;
}

int
main(int argc, char *argv[])
{
	const struct gotctl_cmd *cmd;
	int gotd_sock = -1, i;
	int ch;
	int hflag = 0, Vflag = 0;
	static const struct option longopts[] = {
	    { "version", no_argument, NULL, 'V' },
	    { NULL, 0, NULL, 0 }
	};
	const char *socket_path = GOTD_UNIX_SOCKET;

	setlocale(LC_CTYPE, "");

#ifndef PROFILE
	if (pledge("stdio unix unveil", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt_long(argc, argv, "+hf:V", longopts, NULL)) != -1) {
		switch (ch) {
		case 'h':
			hflag = 1;
			break;
		case 'f':
			socket_path = optarg;
			break;
		case 'V':
			Vflag = 1;
			break;
		default:
			usage(hflag, 1);
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;
	optind = 1;
	optreset = 1;

	if (Vflag) {
		got_version_print_str();
		return 0;
	}

	if (argc <= 0)
		usage(hflag, hflag ? 0 : 1);

	for (i = 0; i < nitems(gotctl_commands); i++) {
		const struct got_error *error;

		cmd = &gotctl_commands[i];

		if (strncmp(cmd->cmd_name, argv[0], strlen(argv[0])) != 0)
			continue;

		if (hflag)
			cmd->cmd_usage();

		gotd_sock = connect_gotd(socket_path);
		if (gotd_sock == -1)
			return 1;
		error = cmd->cmd_main(argc, argv, gotd_sock);
		close(gotd_sock);
		if (error) {
			fprintf(stderr, "%s: %s\n", getprogname(), error->msg);
			return 1;
		}

		return 0;
	}

	fprintf(stderr, "%s: unknown command '%s'\n", getprogname(), argv[0]);
	list_commands(stderr);
	return 1;
}
