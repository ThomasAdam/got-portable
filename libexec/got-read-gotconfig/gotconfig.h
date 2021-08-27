/*
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

struct fetch_repo {
	char	*fetch_repository;
	char	*fetch_server;
	char	*fetch_protocol;
	int	fetch_port;
	struct	node_branch *fetch_branch;
};

struct send_repo {
	char	*send_repository;
	char	*send_server;
	char	*send_protocol;
	int	send_port;
	struct	node_branch *send_branch;
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
	struct	node_ref *ref;
	struct	fetch_repo *fetch_repo;
	struct	send_repo *send_repo;
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
