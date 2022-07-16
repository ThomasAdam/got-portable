/*	$OpenBSD: rcsutil.c,v 1.46 2017/08/29 16:47:33 otto Exp $	*/
/*
 * Copyright (c) 2005, 2006 Joris Vink <joris@openbsd.org>
 * Copyright (c) 2006 Xavier Santolaria <xsa@openbsd.org>
 * Copyright (c) 2006 Niall O'Higgins <niallo@openbsd.org>
 * Copyright (c) 2006 Ray Lai <ray@openbsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL  DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/queue.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "got_compat.h"

#include "buf.h"
#include "rcsutil.h"

/*
 * Split the contents of a file into a list of lines.
 */
struct rcs_lines *
rcs_splitlines(u_char *data, size_t len)
{
	u_char *c, *p;
	struct rcs_lines *lines;
	struct rcs_line *lp;
	size_t i, tlen;

	lines = calloc(1, sizeof(*lines));
	if (lines == NULL)
		return NULL;
	TAILQ_INIT(&(lines->l_lines));

	lp = calloc(1, sizeof(*lp));
	if (lp == NULL) {
		free(lines);
		return NULL;
	}
	TAILQ_INSERT_TAIL(&(lines->l_lines), lp, l_list);

	p = c = data;
	for (i = 0; i < len; i++) {
		if (*p == '\n' || (i == len - 1)) {
			tlen = p - c + 1;
			lp = malloc(sizeof(*lp));
			if (lp == NULL) {
				rcs_freelines(lines);
				return NULL;
			}
			lp->l_line = c;
			lp->l_len = tlen;
			lp->l_lineno = ++(lines->l_nblines);
			TAILQ_INSERT_TAIL(&(lines->l_lines), lp, l_list);
			c = p + 1;
		}
		p++;
	}

	return (lines);
}

void
rcs_freelines(struct rcs_lines *lines)
{
	struct rcs_line *lp;

	while ((lp = TAILQ_FIRST(&(lines->l_lines))) != NULL) {
		TAILQ_REMOVE(&(lines->l_lines), lp, l_list);
		free(lp);
	}

	free(lines);
}

BUF *
rcs_patchfile(u_char *data, size_t dlen, u_char *patch, size_t plen,
    int (*p)(struct rcs_lines *, struct rcs_lines *))
{
	const struct got_error *err = NULL;
	struct rcs_lines *dlines, *plines;
	struct rcs_line *lp;
	BUF *res;
	size_t newlen;

	dlines = rcs_splitlines(data, dlen);
	plines = rcs_splitlines(patch, plen);

	if (p(dlines, plines) < 0) {
		rcs_freelines(dlines);
		rcs_freelines(plines);
		return (NULL);
	}

	err = buf_alloc(&res, 1024);
	if (err)
		return NULL;
	TAILQ_FOREACH(lp, &dlines->l_lines, l_list) {
		if (lp->l_line == NULL)
			continue;
		buf_append(&newlen, res, lp->l_line, lp->l_len);
	}

	rcs_freelines(dlines);
	rcs_freelines(plines);
	return (res);
}
