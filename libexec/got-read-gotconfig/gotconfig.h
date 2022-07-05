/*
 * Copyright (c) 2022 Josh Rickmar <jrick@zettaport.com>
 * Copyright (c) 2020, 2021 Tracey Emery <tracey@openbsd.org>
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

/*
 * We maintain two different structures for fetch and send configuration
 * settings in case they diverge in the future.
 */
struct fetch_config {
	char	*repository;
	char	*server;
	char	*protocol;
	int	port;
	struct	node_branch *branch;
};
struct send_config {
	char	*repository;
	char	*server;
	char	*protocol;
	int	port;
	struct	node_branch *branch;
};

struct node_branch {
	char *branch_name;
	struct node_branch *next;
	struct node_branch *tail;
};

struct node_ref {
	char *ref_name;
	struct node_ref *next;
	struct node_ref *tail;
};

struct gotconfig_remote_repo {
	TAILQ_ENTRY(gotconfig_remote_repo) entry;
	char	*name;
	char	*repository;
	char	*server;
	char	*protocol;
	int	port;
	int	mirror_references;
	int	fetch_all_branches;
	struct	node_branch *branch;
	struct	node_ref *fetch_ref;
	struct	fetch_config *fetch_config;
	struct	send_config *send_config;
};
TAILQ_HEAD(gotconfig_remote_repo_list, gotconfig_remote_repo);

struct gotconfig {
	char	*author;
	struct gotconfig_remote_repo_list remotes;
	int nremotes;
	char	*allowed_signers_file;
	char	*revoked_signers_file;
	char	*signer_id;
};

/*
 * Parse individual gotconfig repository files
 */
const struct got_error *gotconfig_parse(struct gotconfig **, const char *,
    int *);
void gotconfig_free(struct gotconfig *);
