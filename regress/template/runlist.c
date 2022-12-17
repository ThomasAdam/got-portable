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
#include "lists.h"

int	base(struct template *, struct tailhead *);
int	my_putc(struct template *, int);
int	my_puts(struct template *, const char *);

int
my_putc(struct template *tp, int c)
{
	FILE	*fp = tp->tp_arg;

	if (putc(c, fp) < 0)
		return (-1);

	return (0);
}

int
my_puts(struct template *tp, const char *s)
{
	FILE	*fp = tp->tp_arg;

	if (fputs(s, fp) < 0)
		return (-1);

	return (0);
}

int
main(int argc, char **argv)
{
	struct template	*tp;
	struct tailhead	 head;
	struct entry	*np;
	int		 i;

	if ((tp = template(stdout, my_puts, my_putc)) == NULL)
		err(1, "template");

	TAILQ_INIT(&head);
	for (i = 0; i < 2; ++i) {
		if ((np = calloc(1, sizeof(*np))) == NULL)
			err(1, "calloc");
		if (asprintf(&np->text, "%d", i+1) == -1)
			err(1, "asprintf");
		TAILQ_INSERT_TAIL(&head, np, entries);
	}

	if (base(tp, &head) == -1)
		return (1);
	puts("");

	while ((np = TAILQ_FIRST(&head))) {
		TAILQ_REMOVE(&head, np, entries);
		free(np->text);
		free(np);
	}

	if (base(tp, &head) == -1)
		return (1);
	puts("");

	free(tp);

	return (0);
}
