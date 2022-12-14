/*
 * Copyright (c) 2022 Omar Polo <op@omarpolo.com>
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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#include "tmpl.h"

int
tp_urlescape(struct template *tp, const char *str)
{
	int	 r;
	char	 tmp[4];

	if (str == NULL)
		return (0);

	for (; *str; ++str) {
		if (iscntrl((unsigned char)*str) ||
		    isspace((unsigned char)*str) ||
		    *str == '\'' || *str == '"' || *str == '\\') {
			r = snprintf(tmp, sizeof(tmp), "%%%2X", *str);
			if (r < 0  || (size_t)r >= sizeof(tmp))
				return (0);
			if (tp->tp_puts(tp, tmp) == -1)
				return (-1);
		} else {
			if (tp->tp_putc(tp, *str) == -1)
				return (-1);
		}
	}

	return (0);
}

int
tp_htmlescape(struct template *tp, const char *str)
{
	int r;

	if (str == NULL)
		return (0);

	for (; *str; ++str) {
		switch (*str) {
		case '<':
			r = tp->tp_puts(tp, "&lt;");
			break;
		case '>':
			r = tp->tp_puts(tp, "&gt;");
			break;
		case '&':
			r = tp->tp_puts(tp, "&amp;");
			break;
		case '"':
			r = tp->tp_puts(tp, "&quot;");
			break;
		case '\'':
			r = tp->tp_puts(tp, "&apos;");
			break;
		default:
			r = tp->tp_putc(tp, *str);
			break;
		}

		if (r == -1)
			return (-1);
	}

	return (0);
}

struct template *
template(void *arg, tmpl_puts putsfn, tmpl_putc putcfn)
{
	struct template *tp;

	if ((tp = calloc(1, sizeof(*tp))) == NULL)
		return (NULL);

	tp->tp_arg = arg;
	tp->tp_escape = tp_htmlescape;
	tp->tp_puts = putsfn;
	tp->tp_putc = putcfn;

	return (tp);
}

void
template_free(struct template *tp)
{
	free(tp->tp_tmp);
	free(tp);
}
