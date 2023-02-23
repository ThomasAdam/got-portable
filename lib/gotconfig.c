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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <sys/socket.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <imsg.h>
#include <sha1.h>
#include <sha2.h>
#include <limits.h>

#include "got_compat.h"

#include "got_error.h"
#include "got_object.h"
#include "got_repository.h"

#include "got_lib_gotconfig.h"

#include "got_gotconfig.h"

void
got_gotconfig_free(struct got_gotconfig *conf)
{
	int i;

	if (conf == NULL)
		return;

	free(conf->author);

	for (i = 0; i < conf->nremotes; i++)
		got_repo_free_remote_repo_data(&conf->remotes[i]);
	free(conf->remotes);
	free(conf);
}

const char *
got_gotconfig_get_author(const struct got_gotconfig *conf)
{
	return conf->author;
}

void
got_gotconfig_get_remotes(int *nremotes, const struct got_remote_repo **remotes,
    const struct got_gotconfig *conf)
{
	*nremotes = conf->nremotes;
	*remotes = conf->remotes;
}

const char *
got_gotconfig_get_allowed_signers_file(const struct got_gotconfig *conf)
{
	return conf->allowed_signers_file;
}

const char *
got_gotconfig_get_revoked_signers_file(const struct got_gotconfig *conf)
{
	return conf->revoked_signers_file;
}

const char *
got_gotconfig_get_signer_id(const struct got_gotconfig *conf)
{
	return conf->signer_id;
}
