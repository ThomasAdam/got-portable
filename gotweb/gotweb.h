/*
 * Copyright (c) 2019, 2020 Tracey Emery <tracey@traceyemery.net>
 * Copyright (c) 2018, 2019 Stefan Sperling <stsp@openbsd.org>
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

#ifndef GOTWEB_H
#define GOTWEB_H

#include <stdbool.h>

#include <got_error.h>

#define	GOTWEB_CONF	 "/etc/gotweb.conf"
#define GOTWEB_TMPL_DIR	 "/cgi-bin/gw_tmpl"
#define GOTWEB		 "/cgi-bin/gotweb/gotweb"

#define GOTWEB_GOT_DIR	 ".got"
#define GOTWEB_GIT_DIR	 ".git"

#define D_GOTPATH	 "/got/public"
#define D_SITENAME	 "Gotweb"
#define D_SITEOWNER	 "Got Owner"
#define D_SITELINK	 "Repos"
#define D_GOTLOGO	 "got.png"
#define D_GOTURL	 "https://gameoftrees.org"

#define	D_SHOWROWNER	 true
#define	D_SHOWSOWNER	 true
#define D_SHOWAGE	 true
#define D_SHOWDESC	 true
#define D_SHOWURL	 true
#define	D_MAXREPO	 0
#define D_MAXREPODISP	 25
#define D_MAXSLCOMMDISP	 10
#define D_MAXCOMMITDISP	 25

#define BUFFER_SIZE	 2048

struct gotweb_conf {
	char		*got_repos_path;
	char		*got_site_name;
	char		*got_site_owner;
	char		*got_site_link;
	char		*got_logo;
	char		*got_logo_url;

	size_t		 got_max_repos;
	size_t		 got_max_repos_display;
	size_t		 got_max_commits_display;

	bool		 got_show_site_owner;
	bool		 got_show_repo_owner;
	bool		 got_show_repo_age;
	bool		 got_show_repo_description;
	bool		 got_show_repo_cloneurl;
};

const struct got_error*	 parse_conf(const char *, struct gotweb_conf *);

#endif /* GOTWEB_H */
