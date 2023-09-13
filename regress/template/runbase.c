/*
 * Copyright (c) 2022 Omar Polo <op@openbsd.org>
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

#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include "tmpl.h"

int	 base(struct template *, const char *title);
int	 my_write(void *, const void *, size_t);

int
my_write(void *arg, const void *s, size_t len)
{
	FILE	*fp = arg;

	if (fwrite(s, 1, len, fp) < 0)
		return (-1);

	return (0);
}

int
main(int argc, char **argv)
{
	struct template	*tp;
	char		 buf[3];
	/* use a ridiculously small buffer in regress */

	if ((tp = template(stdout, my_write, buf, sizeof(buf))) == NULL)
		err(1, "template");

	if (base(tp, " *hello* ") == -1 ||
	    template_flush(tp) == -1)
		return (1);
	puts("");

	if (base(tp, "<hello>") == -1 ||
	    template_flush(tp) == -1)
		return (1);
	puts("");

	template_free(tp);
	return (0);
}
