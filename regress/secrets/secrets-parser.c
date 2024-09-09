/*
 * Copyright (c) 2024 Omar Polo <op@openbsd.org>
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

#include <err.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>

#include "got_error.h"

#include "log.h"
#include "secrets.h"

static void __dead
usage(void)
{
	fprintf(stderr, "usage: %s [-v] file\n", getprogname());
	exit(1);
}

int
main(int argc, char **argv)
{
	const struct got_error	*error;
	struct gotd_secrets	*secrets;
	struct gotd_secret	*secret;
	FILE			*fp;
	size_t			 i;
	int			 ch, verbose = 0;

	if (pledge("stdio rpath", NULL) == -1)
		err(1, "pledge");

	while ((ch = getopt(argc, argv, "v")) != -1) {
		switch (ch) {
		case 'v':
			verbose = 1;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	log_init(1, LOG_USER);
	log_procinit("secrets");
	log_setverbose(verbose);

	if ((fp = fopen(argv[0], "r")) == NULL)
		err(1, "can't open %s", argv[0]);

	if ((error = gotd_secrets_parse(argv[0], fp, &secrets)) != NULL)
		errx(1, "failed to parse %s: %s", argv[0], error->msg);

	for (i = 0; i < secrets->len; ++i) {
		secret = &secrets->secrets[i];

		if (secret->type == GOTD_SECRET_AUTH) {
			printf("auth %s user %s password %s\n",
			    secret->label, secret->user, secret->pass);
		} else {
			printf("hmac %s %s\n", secret->label, secret->hmac);
		}
	}

	gotd_secrets_free(secrets);
	return 0;
}
