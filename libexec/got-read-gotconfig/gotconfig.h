/*
 * Copyright (c) 2020 Tracey Emery <tracey@openbsd.org>
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

struct gotconfig_remote_repo {
	TAILQ_ENTRY(gotconfig_remote_repo) entry;
	char	*name;
	char	*repository;
	char	*server;
	char	*protocol;
	int	port;
	int	mirror_references;
};
TAILQ_HEAD(gotconfig_remote_repo_list, gotconfig_remote_repo);

struct gotconfig {
	char	*author;
	struct gotconfig_remote_repo_list remotes;
	int nremotes;
};

/*
 * Parse individual gotconfig repository files
 */
const struct got_error *gotconfig_parse(struct gotconfig **, const char *,
    int *);
void gotconfig_free(struct gotconfig *);
