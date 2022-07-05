/*
 * Copyright (c) 2020 Stefan Sperling <stsp@openbsd.org>
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

struct got_gotconfig;

/*
 * Obtain the commit author parsed from got.conf.
 * Return NULL if no configuration file or author could be found.
 */
const char *got_gotconfig_get_author(const struct got_gotconfig *);

/*
 * Obtain the list of remote repositories parsed from got.conf.
 * Return 0 and NULL if no configuration file or remote repository
 * could be found.
 */
void got_gotconfig_get_remotes(int *, const struct got_remote_repo **,
    const struct got_gotconfig *);

/*
 * Obtain the filename of the allowed signers file.
 * Returns NULL if no configuration file is found or no allowed signers file
 * is configured.
 */
const char *
got_gotconfig_get_allowed_signers_file(const struct got_gotconfig *);

/*
 * Obtain the filename of the revoked signers file.
 * Returns NULL if no configuration file is found or no revoked signers file
 * is configured.
 */
const char *
got_gotconfig_get_revoked_signers_file(const struct got_gotconfig *);

/*
 * Obtain the signer identity used to sign tag objects
 * Returns NULL if no configuration file is found or no revoked signers file
 * is configured.
 */
const char *
got_gotconfig_get_signer_id(const struct got_gotconfig *);
