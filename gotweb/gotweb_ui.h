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
