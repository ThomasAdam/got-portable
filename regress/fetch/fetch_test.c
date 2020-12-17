/*
 * Copyright (c) 2020 Stefan Sperling <stsp@openbsd.org>
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

#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <sha1.h>
#include <zlib.h>
#include <time.h>

#include "got_error.h"
#include "got_object.h"
#include "got_path.h"
#include "got_fetch.h"

#include "got_lib_object_idset.h"
#include "got_lib_sha1.h"
#include "got_lib_inflate.h"
#include "got_lib_delta.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

static int verbose;
static int quiet;

void
test_printf(char *fmt, ...)
{
	va_list ap;

	if (!verbose)
		return;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

static int
fetch_parse_uri(void)
{
	const struct got_error *err = NULL;
	struct parse_uri_test {
		const char *uri;
		const char *proto;
		const char *host;
		const char *port;
		const char *server_path;
		const char *repo_name;
		int errcode;
	} test_data[] = {
		{ "", NULL, NULL, NULL, NULL, NULL, GOT_ERR_PARSE_URI },
		{ "git:", NULL, NULL, NULL, NULL, NULL, GOT_ERR_PARSE_URI },
		{ "git://localhost/",
		    NULL, NULL, NULL, NULL, NULL, GOT_ERR_PARSE_URI },
		{ "git://localhost////",
		    NULL, NULL, NULL, NULL, NULL, GOT_ERR_PARSE_URI },
		{ "git://127.0.0.1/git/",
		    NULL, NULL, NULL, NULL, NULL, GOT_ERR_PARSE_URI },
		{ "git:///127.0.0.1/git/",
		    NULL, NULL, NULL, NULL, NULL, GOT_ERR_PARSE_URI },
		{ "/127.0.0.1:/git/",
		    NULL, NULL, NULL, NULL, NULL, GOT_ERR_PARSE_URI },

		{ "git://127.0.0.1/git/myrepo",
		    "git", "127.0.0.1", NULL,
		    "/git/myrepo", "myrepo", GOT_ERR_OK },
		{ "git://127.0.0.1//git/myrepo",
		    "git", "127.0.0.1", NULL,
		    "/git/myrepo", "myrepo", GOT_ERR_OK },
		{ "git://127.0.0.1/////git//myrepo",
		    "git", "127.0.0.1", NULL,
		    "/git//myrepo", "myrepo", GOT_ERR_OK },
		{ "http://127.0.0.1/git/myrepo",
		    "http", "127.0.0.1", NULL,
		    "/git/myrepo", "myrepo", GOT_ERR_OK },
		{ "gopher://127.0.0.1/git/myrepo",
		    "gopher", "127.0.0.1", NULL,
		    "/git/myrepo", "myrepo", GOT_ERR_OK },

		{ "git://127.0.0.1:22/git/myrepo",
		    "git", "127.0.0.1", "22", "/git/myrepo", "myrepo",
		    GOT_ERR_OK },
		{ "git://127.0.0.1/git/repos/foo/bar/myrepo.git",
		    "git", "127.0.0.1", NULL,
		    "/git/repos/foo/bar/myrepo.git", "myrepo", GOT_ERR_OK },
		{ "https://127.0.0.1/git/repos/foo/../bar/myrepo.git",
		    "https", "127.0.0.1", NULL,
		    "/git/repos/foo/../bar/myrepo.git", "myrepo",
		    GOT_ERR_OK },

		{ "git+ssh://127.0.0.1:22/git/myrepo",
		    "git+ssh", "127.0.0.1", "22", "/git/myrepo", "myrepo",
		    GOT_ERR_OK },
		{ "ssh://127.0.0.1:22/git/myrepo",
		    "ssh", "127.0.0.1", "22", "/git/myrepo", "myrepo",
		    GOT_ERR_OK },

		{ "127.0.0.1:git/myrepo",
		    "ssh", "127.0.0.1", NULL, "git/myrepo", "myrepo",
		    GOT_ERR_OK },
		{ "127.0.0.1:/git/myrepo",
		    "ssh", "127.0.0.1", NULL, "/git/myrepo", "myrepo",
		    GOT_ERR_OK },
		{ "127.0.0.1:22/git/myrepo",
		    "ssh", "127.0.0.1", NULL, "22/git/myrepo", "myrepo",
		    GOT_ERR_OK },
	};
	size_t i;

	for (i = 0; i < nitems(test_data); i++) {
		const char *uri = test_data[i].uri;
		const char *expected_proto = test_data[i].proto;
		const char *expected_host = test_data[i].host;
		const char *expected_port = test_data[i].port;
		const char *expected_server_path = test_data[i].server_path;
		const char *expected_repo_name = test_data[i].repo_name;
		char *proto, *host, *port, *server_path, *repo_name;

		err = got_fetch_parse_uri(&proto, &host, &port, &server_path,
		    &repo_name, uri);
		if (err && err->code != test_data[i].errcode) {
			test_printf("%d: error code %d; expected %d\n",
			    i, err->code, test_data[i].errcode);
			return 0;
		}

		if (expected_proto == NULL && proto != NULL) {
			test_printf("%d: proto %s; expected NULL\n", i, proto);
			return 0;
		}
		if (expected_host == NULL && host != NULL) {
			test_printf("%d: host %s; expected NULL\n", i, host);
			return 0;
		}
		if (expected_port == NULL && port != NULL) {
			test_printf("%d: port %s; expected NULL\n", i, port);
			return 0;
		}
		if (expected_server_path == NULL && server_path != NULL) {
			test_printf("%d: server path %s; expected NULL\n", i,
			    server_path);
			return 0;
		}
		if (expected_repo_name == NULL && repo_name != NULL) {
			test_printf("%d: repo name %s; expected NULL\n", i,
			    repo_name);
			return 0;
		}

		if (expected_proto != NULL && proto == NULL) {
			test_printf("%d: proto NULL; expected %s\n", i,
			    expected_proto);
			return 0;
		}
		if (expected_host != NULL && host == NULL) {
			test_printf("%d: host NULL; expected %s\n", i,
			    expected_host);
			return 0;
		}
		if (expected_port != NULL && port == NULL) {
			test_printf("%d: port NULL; expected %s\n", i,
			    expected_port);
			return 0;
		}
		if (expected_server_path != NULL && server_path == NULL) {
			test_printf("%d: server path %s; expected %s\n", i,
			    expected_server_path);
			return 0;
		}
		if (expected_repo_name != NULL && repo_name == NULL) {
			test_printf("%d: repo name NULL; expected %s\n", i,
			    repo_name);
			return 0;
		}

		if (expected_proto != NULL && strcmp(expected_proto, proto)) {
			test_printf("%d: proto %s; expected %s\n", i, proto,
			    expected_proto);
			return 0;
		}

		if (expected_host != NULL && strcmp(expected_host, host)) {
			test_printf("%d: host %s; expected %s\n", i, host,
			    expected_host);
			return 0;
		}

		if (expected_port != NULL && strcmp(expected_port, port)) {
			test_printf("%d: port %s; expected %s\n", i, port,
			    expected_port);
			return 0;
		}

		if (expected_server_path != NULL &&
		    strcmp(expected_server_path, server_path)) {
			test_printf("%d: server_path %s; expected %s\n", i,
			    server_path, expected_server_path);
			return 0;
		}

		if (expected_repo_name != NULL &&
		    strcmp(expected_repo_name, repo_name)) {
			test_printf("%d: repo_name %s; expected %s\n", i,
			    repo_name, expected_repo_name);
			return 0;
		}

		free(proto);
		proto = NULL;
		free(host);
		host = NULL;
		free(port);
		port = NULL;
		free(server_path);
		server_path = NULL;
		free(repo_name);
		repo_name = NULL;
	}

	return 1;
}

#define RUN_TEST(expr, name) \
	{ test_ok = (expr);  \
	if (!quiet) printf("test_%s %s\n", (name), test_ok ? "ok" : "failed"); \
	failure = (failure || !test_ok); }

void
usage(void)
{
	fprintf(stderr, "usage: fetch_test [-v] [-q]\n");
}

int
main(int argc, char *argv[])
{
	int test_ok = 0, failure = 0;
	int ch;

#ifndef PROFILE
	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");
#endif

	while ((ch = getopt(argc, argv, "vq")) != -1) {
		switch (ch) {
		case 'v':
			verbose = 1;
			quiet = 0;
			break;
		case 'q':
			quiet = 1;
			verbose = 0;
			break;
		default:
			usage();
			return 1;
		}
	}
	argc -= optind;
	argv += optind;

	RUN_TEST(fetch_parse_uri(), "fetch_parse_uri");

	return failure ? 1 : 0;
}
