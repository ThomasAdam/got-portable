/*
 * Copyright (c) 2022 Stefan Sperling <stsp@openbsd.org>
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

#include <sys/socket.h>
#include <netinet/in.h>

#include <string.h>

#include "got_sockaddr.h"

/*
 * These interfaces wrap BSD-specific internals of internet address
 * data structures in a single compilation unit, allowing got-portable
 * to override them as needed, without a need for #ifdef macros.
 */

void
got_sockaddr_inet_init(struct sockaddr_in *in, struct in_addr *ina)
{
	in->sin_len = sizeof(struct sockaddr_in); /* BSD-specific */
	in->sin_family = AF_INET;
	in->sin_addr.s_addr = ina->s_addr;
}

void
got_sockaddr_inet6_init(struct sockaddr_in6 *in6, struct in6_addr *in6a,
    uint32_t sin6_scope_id)
{
	in6->sin6_len = sizeof(struct sockaddr_in6); /* BSD-specific */
	in6->sin6_family = AF_INET6;
	memcpy(&in6->sin6_addr, in6a, sizeof(in6->sin6_addr));
	in6->sin6_scope_id = sin6_scope_id;
}
