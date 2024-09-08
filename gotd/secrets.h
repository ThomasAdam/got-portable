/*
 * Copyright (c) 2024 Omar Polo <op@openbsd.org>
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

enum gotd_secret_type {
	GOTD_SECRET_AUTH,
	GOTD_SECRET_HMAC,
};

struct gotd_secret {
	enum gotd_secret_type	 type;
	char			*key;	/* label or username		*/
	char			*val;	/* hmac secret or password	*/
};

struct gotd_secrets {
	struct gotd_secret	*secrets;
	size_t			 len;
	size_t			 cap;
};

const struct got_error *gotd_secrets_parse(const char *, FILE *,
    struct gotd_secrets **);
const char *gotd_secrets_get(struct gotd_secrets *, enum gotd_secret_type,
    const char *);
void gotd_secrets_free(struct gotd_secrets *);
