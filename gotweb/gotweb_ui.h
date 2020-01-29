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

char *site_owner =
	"<div id='site_owner_wrapper'><div id='site_owner'>%s</div></div>";

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

char *div_diff_line =
	"<div id='diff_line' class='%s'>";

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
	"<a href='?path=%s&action=%s&commit=%s&folder=/%s' " \
	    "class='diff_directory'>%s%s</a>";

char *file_html =
	"<a href='?path=%s&action=%s&commit=%s&file=%s&folder=/%s'>%s%s</a>";

/* headers */

char *header_commit_html =
	"<div id='header_commit_title'>Commit:</div>" \
	"<div id='header_commit'>%s %s</div>";

char *header_diff_html =
	"<div id='header_diff_title'>Diff:</div>" \
	"<div id='header_diff'>%s %s</div>";

char *header_author_html =
	"<div id='header_author_title'>Author:</div>" \
	"<div id='header_author'>%s</div>";

char *header_committer_html =
	"<div id='header_committer_title'>Committer:</div>" \
	"<div id='header_committer'>%s</div>";

char *header_age_html =
	"<div id='header_age_title'>Date:</div>" \
	"<div id='header_age'>%s</div>";

char *header_commit_msg_html =
	"<div id='header_commit_msg_title'>Message:</div>" \
	"<div id='header_commit_msg'>%s</div>";

char *header_tree_html =
	"<div id='header_tree_title'>Tree:</div>" \
	"<div id='header_tree'>%s</div>";

/* commit.tmpl */

char *commits_wrapper =
	"<div id='commits_title_wrapper'>" \
	"<div id='commits_title'>Commits</div></div>" \
	"<div id='commits_content'>";

char *commits_line =
	"<div id='commits_line_wrapper'>%s%s%s%s</div>" \
	"<div id='dotted_line'></div>" \
	"<div id='commit'>%s</div>" \
	"<div id='navs_wrapper'>" \
	"<div id='navs'>%s</div>" \
	"</div>" \
	"</div>" \
	"<div id='solid_line'></div>";

char *commits_navs =
	"<a href='?path=%s&action=diff&commit=%s'>diff</a> | " \
	"<a href='?path=%s&action=tree&commit=%s'>tree</a><!--/* | " \
	"<a href='?path=%s&action=snapshot&commit=%s'>snapshot</a> */-->";

/* briefs.tmpl */

char *briefs_wrapper =
	"<div id='briefs_title_wrapper'>" \
	"<div id='briefs_title'>Commit Briefs</div></div>" \
	"<div id='briefs_content'>";

char *briefs_line =
	"<div id='briefs_wrapper'>" \
	"<div id='briefs_age'>%s</div>" \
	"<div id='briefs_author'>%s</div>" \
	"<div id='briefs_log'>%s</div>" \
	"</div>" \
	"<div id='navs_wrapper'>" \
	"<div id='navs'>%s</div>" \
	"</div>" \
	"</div>" \
	"<div id='dotted_line'></div>";

char *briefs_navs =
	"<a href='?path=%s&action=diff&commit=%s'>diff</a> | " \
	"<a href='?path=%s&action=tree&commit=%s'>tree</a><!--/* | " \
	"<a href='?path=%s&action=snapshot&commit=%s'>snapshot</a> */-->";

/* blob.tmpl */

char *blob_wrapper =
	"<div id='blob_title_wrapper'>" \
	"<div id='blob_title'>Blob</div></div>" \
	"<div id='blob_content'>%s</div>";

char *blob_header =
	"<div id='blob_header_wrapper'>" \
	"<div id='blob_header'>%s%s</div>" \
	"</div>" \
	"<div id='dotted_line'></div>" \
	"<div id='blob'>%s</div>" \
	"</div>";

char *blob_line =
	"<div id='blob_wrapper'>" \
	"<div id='blob_number'>%.*d</div>" \
	"<div id='blob_hash'>%.8s</div>" \
	"<div id='blob_date'>%s</div>" \
	"<div id='blob_author'>%-8s</div>" \
	"<div id='blob_code'>%s</div>" \
	"</div>";

/* blame.tmpl */

char *blame_wrapper =
	"<div id='blame_title_wrapper'>" \
	"<div id='blame_title'>Blame</div></div>" \
	"<div id='blame_content'>%s</div>";

char *blame_header =
	"<div id='blame_header_wrapper'>" \
	"<div id='blame_header'>%s%s</div>" \
	"</div>" \
	"<div id='dotted_line'></div>" \
	"<div id='blame'>%s</div>" \
	"</div>";

char *blame_line =
	"<div id='blame_wrapper'>" \
	"<div id='blame_number'>%.*d</div>" \
	"<div id='blame_hash'>%.8s</div>" \
	"<div id='blame_date'>%s</div>" \
	"<div id='blame_author'>%-8s</div>" \
	"<div id='blame_code'>%s</div>" \
	"</div>";

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
	"<a href='?path=%s&action=%s&commit=%s&file=%s&folder=/%s'>%s</a> | " \
	"<a href='?path=%s&action=%s&commit=%s&file=%s&folder=/%s'>%s</a>" \
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

/* diff.tmpl */

char *diff_wrapper =
	"<div id='diff_title_wrapper'>" \
	"<div id='diff_title'>Commit Diff</div></div>" \
	"<div id='diff_content'>%s</div>";

char *diff_header =
	"<div id='diff_header_wrapper'>" \
	"<div id='diff_header'>%s%s%s%s%s%s%s</div>" \
	"</div>" \
	"<div id='dotted_line'></div>" \
	"<div id='diff'>%s</div>" \
	"</div>";

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

/* summary.tmpl */

char *summary_wrapper =
	"<div id='summary_wrapper'>";

char *summary_tags =
	"<div id='summary_tags_title_wrapper'>" \
	"<div id='summary_tags_title'>Tags</div></div>" \
	"<div id='summary_tags_content'>%s</div>";

char *summary_heads =
	"<div id='summary_heads_title_wrapper'>" \
	"<div id='summary_heads_title'>Heads</div></div>" \
	"<div id='summary_heads_content'>%s</div>";

#endif /* GOTWEB_UI_H */
