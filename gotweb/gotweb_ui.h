/*
 * Copyright (c) 2019, 2020 Tracey Emery <tracey@traceyemery.net>
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

char *search =
	"<!--/* <div id='search'>" \
	"<form method='POST'>" \
	"<input type='search' id='got-search' name='got-search' size='15'" \
	    " maxlength='50' />" \
	"<button>Search</button>" \
	"</form>" \
	"</div> */-->";

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

char *repo_owner =
	"<div id='repo_owner_title'>Owner: </div>" \
	"<div id='repo_owner'>%s</div>";

char *tags_row =
	"<div id='tags_wrapper'>" \
	"<div id='tags_age'>%s</div>" \
	"<div id='tags'>tag %s</div>" \
	"<div id='tags_name'>%s</div>" \
	"</div>" \
	"<div id='navs_wrapper'>" \
	"<div id='navs'>%s</div>" \
	"</div>" \
	"</div>" \
	"<div id='dotted_line'></div>";

char *tags_navs =
	"<a href='?path=%s&action=tag&commit=%s'>tag</a> | " \
	"<a href='?path=%s&action=briefs&commit=%s'>commit briefs</a> | " \
	"<a href='?path=%s&action=commits&commit=%s'>commits</a>";

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
	"<a href='?path=%s&action=summary&headref=%s'>summary</a> | " \
	"<a href='?path=%s&action=briefs&headref=%s'>commit briefs</a> | " \
	"<a href='?path=%s&action=commits&headref=%s'>commits</a>";

char *folder_html =
	"<a href='?path=%s&action=%s&commit=%s&folder=%s' " \
	    "class='diff_directory'>%s%s</a>";

char *file_html =
	"<a href='?path=%s&action=%s&commit=%s&file=%s&folder=%s'>%s%s</a>";

/* headers */

char *header_commit_html =
	"<div id='header_commit_title'>Commit:</div>" \
	"<div id='header_commit'>%s %s</div>";

char *header_age_html =
	"<div id='header_age_title'>Date:</div>" \
	"<div id='header_age'>%s</div>";

char *header_commit_msg_html =
	"<div id='header_commit_msg_title'>Message:</div>" \
	"<div id='header_commit_msg'>%s</div>";

/* tree.tmpl */

char *tree_wrapper =
	"<div id='tree_title_wrapper'>" \
	"<div id='tree_title'>Tree</div></div>" \
	"<div id='tree_content'>%s</div>";

char *tree_header =
	"<div id='tree_header_wrapper'>" \
	"<div id='tree_header'>%s%s</div>" \
	"</div>" \
	"<div id='dotted_line'></div>" \
	"<div id='tree'>%s</div>" \
	"</div>";

char *tree_line =
	"<div id='tree_wrapper'>" \
	"<div id='tree_line' class='%s'>%s</div>" \
	"<div id='tree_line_blank' class='%s'>&nbsp;</div>" \
	"</div>";

char *tree_line_with_navs =
	"<div id='tree_wrapper'>" \
	"<div id='tree_line' class='%s'>%s</div>" \
	"<div id='tree_line_navs' class='%s'>" \
	"<a href='?path=%s&action=%s&commit=%s&file=%s&folder=%s'>%s</a> | " \
	"<a href='?path=%s&action=%s&commit=%s&file=%s&folder=%s'>%s</a>" \
	"</div>" \
	"</div>";

/* tag.tmpl */

char *tag_wrapper =
	"<div id='tag_title_wrapper'>" \
	"<div id='tag_title'>Tag</div></div>" \
	"<div id='tag_content'>%s</div>";

char *tag_header =
	"<div id='tag_header_wrapper'>" \
	"<div id='tag_header'>%s%s</div>" \
	"</div>" \
	"<div id='dotted_line'></div>" \
	"<div id='tag'>%s</div>" \
	"</div>";

char *tag_line =
	"<div id='tag_wrapper'>" \
	"<div id='tag_line'>%s</div>" \
	"</div>";

char *tag_info =
	"<div id='tag_info_date_title'>Tag Date:</div>" \
	"<div id='tag_info_date'>%s</div>" \
	"<div id='tag_info_tagger_title'>Tagger:</div>" \
	"<div id='tag_info_tagger'>%s</div>" \
	"<div id='tag_info'>%s</div>";

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

char *index_projects_empty =
	"<div id='index_wrapper'>" \
	"No repositories found in %s" \
	"</div>" \
	"<div id='dotted_line'></div>";

char *index_navs =
	"<a href='?path=%s&action=summary'>summary</a> | " \
	"<a href='?path=%s&action=briefs'>commit briefs</a> | " \
	"<a href='?path=%s&action=commits'>commits</a> | " \
	"<a href='?path=%s&action=tree'>tree</a>";

#endif /* GOTWEB_UI_H */
