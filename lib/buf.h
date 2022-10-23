/*	$OpenBSD: buf.h,v 1.13 2011/07/06 15:36:52 nicm Exp $	*/
/*
 * Copyright (c) 2003 Jean-Francois Brousseau <jfb@openbsd.org>
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
 *
 * Buffer management
 * -----------------
 *
 * This code provides an API to generic memory buffer management.  All
 * operations are performed on a buf structure, which is kept opaque to the
 * API user in order to avoid corruption of the fields and make sure that only
 * the internals can modify the fields.
 *
 * The first step is to allocate a new buffer using the buf_alloc()
 * function, which returns a pointer to a new buffer.
 */

#ifndef BUF_H
#define BUF_H

#include <sys/types.h>

typedef struct buf BUF;

struct buf {
	/* buffer handle, buffer size, and data length */
	u_char	*cb_buf;
	size_t	 cb_size;
	size_t	 cb_len;
};

const struct got_error *buf_alloc(BUF **, size_t);
const struct got_error *buf_load(BUF **, FILE *);
const struct got_error *buf_load_fd(BUF **, int fd);
void		 buf_free(BUF *);
void		*buf_release(BUF *);
u_char		 buf_getc(BUF *, size_t);
void		 buf_empty(BUF *);
const struct got_error *buf_discard(BUF *, size_t);
const struct got_error *buf_append(size_t *, BUF *, const void *, size_t);
const struct got_error *buf_putc(BUF *, int);
const struct got_error *buf_puts(size_t *, BUF *b, const char *str);
size_t		 buf_len(BUF *);
int		 buf_write_fd(BUF *, int);
const struct got_error *buf_write(BUF *, const char *, mode_t);
const struct got_error *buf_write_stmp(BUF *, char *);
u_char		*buf_get(BUF *b);

#endif	/* BUF_H */
