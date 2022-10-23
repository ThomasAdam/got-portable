/*
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

#include <sys/types.h>
#include <sys/queue.h>

#include <ctype.h>
#include <string.h>

#include "got_reference.h"

#include "got_lib_lockfile.h"

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

int
got_ref_name_is_valid(const char *name)
{
	const char *s, *seg;
	const char forbidden[] = { ' ', '~', '^', ':', '?', '*', '[' , '\\' };
	const char *forbidden_seq[] = { "//", "..", "@{" };
	const char *lfs = GOT_LOCKFILE_SUFFIX;
	const size_t lfs_len = sizeof(GOT_LOCKFILE_SUFFIX) - 1;
	size_t i;

	if (name[0] == '@' && name[1] == '\0')
		return 0;

	s = name;
	seg = s;
	if (seg[0] == '\0' || seg[0] == '.' || seg[0] == '/')
		return 0;
	while (*s) {
		for (i = 0; i < nitems(forbidden); i++) {
			if (*s == forbidden[i])
				return 0;
		}
		for (i = 0; i < nitems(forbidden_seq); i++) {
			if (s[0] == forbidden_seq[i][0] &&
			    s[1] == forbidden_seq[i][1])
				return 0;
		}
		if (iscntrl((unsigned char)s[0]))
			return 0;
		if (s[0] == '.' && s[1] == '\0')
			return 0;
		if (*s == '/') {
			const char *nextseg = s + 1;
			if (nextseg[0] == '\0' || nextseg[0] == '.' ||
			    nextseg[0] == '/')
				return 0;
			if (seg <= s - lfs_len &&
			    strncmp(s - lfs_len, lfs, lfs_len) == 0)
				return 0;
			seg = nextseg;
		}
		s++;
	}

	if (seg <= s - lfs_len &&
	    strncmp(s - lfs_len, lfs, lfs_len) == 0)
		return 0;

	return 1;
}

