/*
 * Copyright (c) 2021 Stefan Sperling <stsp@openbsd.org>
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

#include <getopt.h>
#include <err.h>
#include <errno.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <util.h>

#include "got_version.h"
#include "got_error.h"
#include "got_object.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_gotconfig.h"
#include "got_path.h"
#include "got_cancel.h"
#include "got_privsep.h"
#include "got_opentemp.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

static volatile sig_atomic_t sigint_received;
static volatile sig_atomic_t sigpipe_received;

static void
catch_sigint(int signo)
{
	sigint_received = 1;
}

static void
catch_sigpipe(int signo)
{
	sigpipe_received = 1;
}


struct gotadmin_cmd {
	const char	*cmd_name;
	const struct got_error *(*cmd_main)(int, char *[]);
	void		(*cmd_usage)(void);
	const char	*cmd_alias;
};

__dead static void	usage(int, int);
__dead static void	usage_info(void);

static const struct got_error*		cmd_info(int, char *[]);

static struct gotadmin_cmd gotadmin_commands[] = {
	{ "info",	cmd_info,	usage_info,	"" },
};

static void
list_commands(FILE *fp)
{
	size_t i;

	fprintf(fp, "commands:");
	for (i = 0; i < nitems(gotadmin_commands); i++) {
		struct gotadmin_cmd *cmd = &gotadmin_commands[i];
		fprintf(fp, " %s", cmd->cmd_name);
	}
	fputc('\n', fp);
}

int
main(int argc, char *argv[])
{
	struct gotadmin_cmd *cmd;
	size_t i;
	int ch;
	int hflag = 0, Vflag = 0;
	static struct option longopts[] = {
	    { "version", no_argument, NULL, 'V' },
	    { NULL, 0, NULL, 0 }
	};

	setlocale(LC_CTYPE, "");

	while ((ch = getopt_long(argc, argv, "+hV", longopts, NULL)) != -1) {
		switch (ch) {
		case 'h':
			hflag = 1;
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

	signal(SIGINT, catch_sigint);
	signal(SIGPIPE, catch_sigpipe);

	for (i = 0; i < nitems(gotadmin_commands); i++) {
		const struct got_error *error;

		cmd = &gotadmin_commands[i];

		if (strcmp(cmd->cmd_name, argv[0]) != 0 &&
		    strcmp(cmd->cmd_alias, argv[0]) != 0)
			continue;

		if (hflag)
			gotadmin_commands[i].cmd_usage();

		error = gotadmin_commands[i].cmd_main(argc, argv);
		if (error && error->code != GOT_ERR_CANCELLED &&
		    error->code != GOT_ERR_PRIVSEP_EXIT &&
		    !(sigpipe_received &&
		      error->code == GOT_ERR_ERRNO && errno == EPIPE) &&
		    !(sigint_received &&
		      error->code == GOT_ERR_ERRNO && errno == EINTR)) {
			fprintf(stderr, "%s: %s\n", getprogname(), error->msg);
			return 1;
		}

		return 0;
	}

	fprintf(stderr, "%s: unknown command '%s'\n", getprogname(), argv[0]);
	list_commands(stderr);
	return 1;
}

__dead static void
usage(int hflag, int status)
{
	FILE *fp = (status == 0) ? stdout : stderr;

	fprintf(fp, "usage: %s [-h] [-V | --version] command [arg ...]\n",
	    getprogname());
	if (hflag)
		list_commands(fp);
	exit(status);
}

static const struct got_error *
apply_unveil(const char *repo_path, int repo_read_only)
{
	const struct got_error *err;

#ifdef PROFILE
	if (unveil("gmon.out", "rwc") != 0)
		return got_error_from_errno2("unveil", "gmon.out");
#endif
	if (repo_path && unveil(repo_path, repo_read_only ? "r" : "rwc") != 0)
		return got_error_from_errno2("unveil", repo_path);

	if (unveil(GOT_TMPDIR_STR, "rwc") != 0)
		return got_error_from_errno2("unveil", GOT_TMPDIR_STR);

	err = got_privsep_unveil_exec_helpers();
	if (err != NULL)
		return err;

	if (unveil(NULL, NULL) != 0)
		return got_error_from_errno("unveil");

	return NULL;
}

__dead static void
usage_info(void)
{
	fprintf(stderr, "usage: %s info [-r repository-path]\n",
	    getprogname());
	exit(1);
}

static const struct got_error *
cmd_info(int argc, char *argv[])
{
	const struct got_error *error = NULL;
	char *cwd = NULL, *repo_path = NULL;
	struct got_repository *repo = NULL;
	const struct got_gotconfig *gotconfig = NULL;
	int ch, npackfiles, npackedobj, nobj;
	off_t packsize, loose_size;
	char scaled[FMT_SCALED_STRSIZE];

	while ((ch = getopt(argc, argv, "r:")) != -1) {
		switch (ch) {
		case 'r':
			repo_path = realpath(optarg, NULL);
			if (repo_path == NULL)
				return got_error_from_errno2("realpath",
				    optarg);
			got_path_strip_trailing_slashes(repo_path);
			break;
		default:
			usage_info();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

#ifndef PROFILE
	if (pledge("stdio rpath wpath flock proc exec sendfd unveil",
	    NULL) == -1)
		err(1, "pledge");
#endif
	cwd = getcwd(NULL, 0);
	if (cwd == NULL) {
		error = got_error_from_errno("getcwd");
		goto done;
	}

	error = got_repo_open(&repo, repo_path ? repo_path : cwd, NULL);
	if (error)
		goto done;

	error = apply_unveil(got_repo_get_path_git_dir(repo), 1);
	if (error)
		goto done;

	printf("repository: %s\n", got_repo_get_path_git_dir(repo));

	gotconfig = got_repo_get_gotconfig(repo);
	if (gotconfig) {
		const struct got_remote_repo *remotes;
		int i, nremotes;
		if (got_gotconfig_get_author(gotconfig)) {
			printf("default author: %s\n",
			    got_gotconfig_get_author(gotconfig));
		}
		got_gotconfig_get_remotes(&nremotes, &remotes, gotconfig);
		for (i = 0; i < nremotes; i++) {
			printf("remote \"%s\": %s\n", remotes[i].name,
			    remotes[i].url);
		}
	}

	error = got_repo_get_packfile_info(&npackfiles, &npackedobj,
	    &packsize, repo);
	if (error)
		goto done;
	printf("pack files: %d\n", npackfiles);
	if (npackfiles > 0) {
		if (fmt_scaled(packsize, scaled) == -1) {
			error = got_error_from_errno("fmt_scaled");
			goto done;
		}
		printf("packed objects: %d\n", npackedobj);
		printf("packed total size: %s\n", scaled);
	}

	error = got_repo_get_loose_object_info(&nobj, &loose_size, repo);
	if (error)
		goto done;
	printf("loose objects: %d\n", nobj);
	if (nobj > 0) {
		if (fmt_scaled(loose_size, scaled) == -1) {
			error = got_error_from_errno("fmt_scaled");
			goto done;
		}
		printf("loose total size: %s\n", scaled);
	}
done:
	if (repo)
		got_repo_close(repo);
	free(cwd);
	return error;
}
