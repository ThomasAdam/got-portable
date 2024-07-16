/*
 * Copyright (c) 2023 Omar Polo <op@openbsd.org>
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

#include "got_compat.h"

#include <sys/queue.h>
#include <sys/types.h>

#include <ctype.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "got_error.h"
#include "got_cancel.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_repository_admin.h" /* XXX for pack_progress */
#include "got_object.h"
#include "got_opentemp.h"
#include "got_repository_dump.h"

#include "got_lib_delta.h"
#include "got_lib_hash.h"
#include "got_lib_object.h"
#include "got_lib_object_idset.h"
#include "got_lib_ratelimit.h"
#include "got_lib_pack_create.h"

#define GIT_BUNDLE_SIGNATURE_V2 "# v2 git bundle"
#define GIT_BUNDLE_SIGNATURE_V3 "# v3 git bundle"

struct idvec {
	struct got_object_id	**ids;
	size_t			  len;
	size_t			  size;
};

static const struct got_error *
idvec_push(struct idvec *v, struct got_object_id *id)
{
	size_t	 newsize;
	void	*t;

	if (v->len == v->size) {
		newsize = v->size + 8;
		t = reallocarray(v->ids, newsize, sizeof(*v->ids));
		if (t == NULL)
			return got_error_from_errno("reallocarray");
		v->ids = t;
		v->size = newsize;
	}

	v->ids[v->len++] = id;
	return NULL;
}

static void
idvec_free(struct idvec *v)
{
	size_t i;

	for (i = 0; i < v->len; ++i)
		free(v->ids[i]);
	free(v->ids);
}

const struct got_error *
got_repo_dump(FILE *out, struct got_reflist_head *include_refs,
    struct got_reflist_head *exclude_refs, struct got_repository *repo,
    got_pack_progress_cb progress_cb, void *progress_arg,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_ratelimit rl;
	struct got_object_id packhash;
	FILE *delta_cache = NULL;
	struct got_reflist_entry *e;
	struct got_object_id *id = NULL;
	struct got_commit_object *commit = NULL;
	struct idvec ours, theirs;
	char *nl, *s, *hex, *logmsg = NULL;
	const char *refname, *signature;
	enum got_hash_algorithm algo;
	int r;

	algo = got_repo_get_object_format(repo);
	switch (algo) {
	case GOT_HASH_SHA1:
		signature = GIT_BUNDLE_SIGNATURE_V2;
		break;
	case GOT_HASH_SHA256:
		signature = GIT_BUNDLE_SIGNATURE_V3;
		break;
	default:
		return got_error(GOT_ERR_OBJECT_FORMAT);
	}

	got_ratelimit_init(&rl, 0, 500);

	memset(&ours, 0, sizeof(ours));
	memset(&theirs, 0, sizeof(theirs));

	r = fprintf(out, "%s\n", signature);
	if (r != strlen(GIT_BUNDLE_SIGNATURE_V2) + 1)
		return got_ferror(out, GOT_ERR_IO);

	if (algo == GOT_HASH_SHA256)
		fprintf(out, "@object-format=sha256\n");

	TAILQ_FOREACH(e, exclude_refs, entry) {
		err = got_ref_resolve(&id, repo, e->ref);
		if (err)
			goto done;

		idvec_push(&theirs, id);
		if (err)
			goto done;

		err = got_object_open_as_commit(&commit, repo, id);
		if (err)
			goto done;

		err = got_object_commit_get_logmsg(&logmsg, commit);
		if (err)
			goto done;

		s = logmsg;
		while (isspace((unsigned char)*s))
			s++;
		nl = strchr(s, '\n');
		if (nl)
			*nl = '\0';

		err = got_object_id_str(&hex, id);
		if (err)
			goto done;
		fprintf(out, "-%s %s\n", hex, s);
		free(hex);

		got_object_commit_close(commit);
		commit = NULL;

		free(logmsg);
		logmsg = NULL;
	}

	TAILQ_FOREACH(e, include_refs, entry) {
		err = got_ref_resolve(&id, repo, e->ref);
		if (err)
			goto done;

		err = idvec_push(&ours, id);
		if (err)
			goto done;

		refname = got_ref_get_name(e->ref);

		err = got_object_id_str(&hex, id);
		if (err)
			goto done;
		fprintf(out, "%s %s\n", hex, refname);
		free(hex);
	}

	if (fputc('\n', out) == EOF || fflush(out) == EOF) {
		err = got_ferror(out, GOT_ERR_IO);
		goto done;
	}

	delta_cache = got_opentemp();
	if (delta_cache == NULL) {
		err = got_error_from_errno("got_opentemp");
		goto done;
	}

	err = got_pack_create(&packhash, fileno(out), delta_cache,
	    theirs.ids, theirs.len, ours.ids, ours.len,
	    repo, 0, 0, 0, progress_cb, progress_arg, &rl,
	    cancel_cb, cancel_arg);

 done:
	idvec_free(&ours);
	idvec_free(&theirs);
	if (commit)
		got_object_commit_close(commit);
	if (delta_cache && fclose(delta_cache) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	return err;
}
