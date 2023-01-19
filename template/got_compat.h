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

#ifndef COMPAT_H
#define COMPAT_H

#ifndef __OpenBSD__
#define pledge(s, p) (0)
#define unveil(s, p) (0)
#endif

#ifndef __dead
#define __dead __attribute__((__noreturn__))
#endif

#ifndef HAVE_ASPRINTF
int		 asprintf(char **, const char *, ...);
int		 vasprintf(char **, const char *, va_list);
#endif

#ifndef HAVE_ERR
__dead void	 err(int, const char *, ...);
__dead void	 errx(int, const char *, ...);
void		 warn(const char *, ...);
void		 warnx(const char *, ...);
#else
# include <err.h>
#endif

#ifndef HAVE_GETPROGNAME
const char	*getprogname(void);
#endif

#ifndef HAVE_REALLOCARRAY
void		*reallocarray(void *, size_t, size_t);
#endif

#endif
