/*
 * Copyright (c) 2019 Tracey Emery <tracey@traceyemery.net>
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
 * header nav
 *
 * ***index
 * search
 * Projects
 * 	Project|Description|Owner|Last Commit
 * 	DIV (summary|shortlog|log|tree)
 * ***summary
 * repo navs | search
 * repo description
 * 	description
 * 	owner
 * 	last commit
 * 	URL
 * shortlog
 * 	Date|committer|commit description (commit|commitdiff|tree|snapshot)
 * heads
 * 	create date | head (shortlog|log|tree)
 *
 *
 *
 * footer
 */

#ifndef GOTWEB_UI_H
#define GOTWEB_UI_H

/* general html */

char *head =
	"<meta name='viewport' content='initial-scale=1.0," \
	    " user-scalable=no' />" \
	"<meta charset='utf-8' />" \
	"<meta name='msapplication-TileColor' content='#da532c' />" \
	"<meta name='theme-color' content='#ffffff' />" \
	"<link rel='apple-touch-icon' sizes='180x180'" \
	    " href='/apple-touch-icon.png' />" \
	"<link rel='icon' type='image/png' sizes='32x32'" \
	    " href='/favicon-32x32.png' />" \
	"<link rel='icon' type='image/png' sizes='16x16'" \
	    " href='/favicon-16x16.png' />" \
	"<link rel='manifest' href='/site.webmanifest' />" \
	"<link rel='mask-icon' href='/safari-pinned-tab.svg'" \
	    " color='#5bbad5' />" \
	"<link rel='stylesheet' type='text/css' href='/gotweb.css' />";

char *got_link =
	"<div id='got_link'>" \
	"<a href='%s' target='_sotd'><img src='/%s' alt='logo' /></a>" \
	"</div>";

char *site_link =
	"<div id='site_link'>" \
	"<a href='%s'>%s</a> %s %s" \
	"</div>";

char *site_owner =
	"<div id='site_owner_wrapper'><div id='site_owner'>%s</div></div>";

char *search =
	"<div id='search'>" \
	"<form method='POST'>" \
	"<input type='search' id='got-search' name='got-search' size='15'" \
	    " maxlength='50' />" \
	"<button>Search</button>" \
	"</form>" \
	"</div>";

char *np_wrapper_start =
	"<div id='np_wrapper'>" \
	"<div id='nav_prev'>";

char *div_end =
	"</div>";

char *nav_next =
	"<div id='nav_next'>" \
	"<a href='?page=%d'>Next<a/>" \
	"</div>";

char *nav_prev =
	"<a href='?page=%d'>Previous<a/>";

char *description =
	"<div id='description_title'>Description: </div>" \
	"<div id='description'>%s</div>";

char *repo_owner =
	"<div id='repo_owner_title'>Owner: </div>" \
	"<div id='repo_owner'>%s</div>";

char *last_change =
	"<div id='last_change_title'>Last Change: </div>" \
	"<div id='last_change'>%s</div>";

char *cloneurl =
	"<div id='cloneurl_title'>Clone URL: </div>" \
	"<div id='cloneurl'>%s</div>";

char *shortlog_row =
	"<div id='shortlog_wrapper'>" \
	"<div id='shortlog_age'>%s</div>" \
	"<div id='shortlog_author'>%s</div>" \
	"<div id='shortlog_log'>%s</div>" \
	"</div>" \
	"<div id='navs_wrapper'>" \
	"<div id='navs'>%s</div>" \
	"</div>" \
	"</div>" \
	"<div id='dotted_line'></div>";

char *shortlog_navs =
	"<a href='?path=%s&action=commit&commit=%s'>commit</a> | " \
	"<a href='?path=%s&action=commitdiff&commit=%s'>commit diff</a> | " \
	"<a href='?path=%s&action=tree&commit=%s'>tree</a> | " \
	"<a href='?path=%s&action=snapshot&commit=%s'>snapshot</a>";

char *tags_row =
	"<div id='tags_wrapper'>" \
	"<div id='tags_age'>%s</div>" \
	"<div id='tag'>%s</div>" \
	"<div id='tag_name'>%s</div>" \
	"</div>" \
	"<div id='navs_wrapper'>" \
	"<div id='navs'>%s</div>" \
	"</div>" \
	"</div>" \
	"<div id='dotted_line'></div>";

char *tags_navs =
	"<a href='?path=%s&action=tagt&commit=%s'>tag</a> | " \
	"<a href='?path=%s&action=commit&commit=%s'>commit</a> | " \
	"<a href='?path=%s&action=shortlog&commit=%s'>shortlog</a> | " \
	"<a href='?path=%s&action=log&commit=%s'>log</a>";

char *heads_row =
	"<div id='heads_wrapper'>" \
	"<div id='heads_age'>%s</div>" \
	"<div id='head'>%s</div>" \
	"</div>" \
	"<div id='navs_wrapper'>" \
	"<div id='navs'>%s</div>" \
	"</div>" \
	"</div>" \
	"<div id='dotted_line'></div>";

char *heads_navs =
	"<a href='?path=%s&action=shortlog&headref=%s'>shortlog</a> | " \
	"<a href='?path=%s&action=log&headref=%s'>log</a> | " \
	"<a href='?path=%s&action=tree&headref=%s'>commit</a>";

/* index.tmpl */

char *index_projects_header =
	"<div id='index_header'>" \
	"<div id='index_header_project'>Project</div>" \
	"<div id='index_header_description'>Description</div>" \
	"<div id='index_header_owner'>Owner</div>" \
	"<div id='index_header_age'>Last Change</div>" \
	"</div>";

char *index_projects =
	"<div id='index_wrapper'>" \
	"<div id='index_project'>" \
	"<a href='?path=%s&action=summary'>%s</a>" \
	"</div>" \
	"<div id='index_project_description'>%s</div>" \
	"<div id='index_project_owner'>%s</div>" \
	"<div id='index_project_age'>%s</div>" \
	"<div id='navs_wrapper'>" \
	"<div id='navs'>%s</div>" \
	"</div>" \
	"</div>" \
	"<div id='dotted_line'></div>";

char *index_navs =
	"<a href='?path=%s&action=summary'>summary</a> | " \
	"<a href='?path=%s&action=shortlog'>shortlog</a> | " \
	"<a href='?path=%s&action=log'>log</a> | " \
	"<a href='?path=%s&action=tree'>tree</a>";

/* summary.tmpl */

char *summary_wrapper =
	"<div id='summary_wrapper'>";

char *summary_shortlog =
	"<div id='summary_shortlog_title_wrapper'>" \
	"<div id='summary_shortlog_title'>Shortlog</div></div>" \
	"<div id='summary_shortlog_content'>%s</div>";

char *summary_tags =
	"<div id='summary_tags_title_wrapper'>" \
	"<div id='summary_tags_title'>Tags</div></div>" \
	"<div id='summary_tags_content'>%s</div>";

char *summary_heads =
	"<div id='summary_heads_title_wrapper'>" \
	"<div id='summary_heads_title'>Heads</div></div>" \
	"<div id='summary_heads_content'>%s</div>";

#endif /* GOTWEB_UI_H */
