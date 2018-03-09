/*
 * Copyright (c) 2017 Stefan Sperling <stsp@openbsd.org>
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

#include <sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <util.h>
#include <zlib.h>

#include "got_error.h"
#include "got_object.h"
#include "got_repository.h"
#include "got_refs.h"

#include "got_sha1_priv.h"
#include "got_path_priv.h"
#include "got_delta_priv.h"
#include "got_zb_priv.h"
#include "got_object_priv.h"

/* A symbolic reference. */
struct got_symref {
	char *name;
	char *ref;
};

/* A non-symbolic reference (there is no better designation). */
struct got_ref {
	char *name;
	u_int8_t sha1[SHA1_DIGEST_LENGTH];
};

/* A reference which points to an arbitrary object. */
struct got_reference {
	unsigned int flags;
#define GOT_REF_IS_SYMBOLIC	0x01

	union {
		struct got_ref ref;
		struct got_symref symref;
	} ref;
};

static const struct got_error *
parse_symref(struct got_reference **ref, const char *name, const char *line)
{
	struct got_symref *symref;
	char *symref_name;
	char *symref_ref;

	if (line[0] == '\0')
		return got_error(GOT_ERR_NOT_REF);

	symref_name = strdup(name);
	if (symref_name == NULL)
		return got_error(GOT_ERR_NO_MEM);
	symref_ref = strdup(line);
	if (symref_ref == NULL) {
		free(symref_name);
		return got_error(GOT_ERR_NO_MEM);
	}

	*ref = calloc(1, sizeof(**ref));
	if (*ref == NULL)
		return got_error(GOT_ERR_NO_MEM);
	(*ref)->flags |= GOT_REF_IS_SYMBOLIC;
	symref = &((*ref)->ref.symref);
	symref->name = symref_name;
	symref->ref = symref_ref;
	return NULL;
}

static const struct got_error *
parse_ref_line(struct got_reference **ref, const char *name, const char *line)
{
	uint8_t digest[SHA1_DIGEST_LENGTH];
	char *ref_name;

	if (strncmp(line, "ref: ", 5) == 0) {
		line += 5;
		return parse_symref(ref, name, line);
	}

	ref_name = strdup(name);
	if (ref_name == NULL)
		return got_error(GOT_ERR_NO_MEM);

	if (!got_parse_sha1_digest(digest, line))
		return got_error(GOT_ERR_NOT_REF);

	*ref = calloc(1, sizeof(**ref));
	if (*ref == NULL)
		return got_error(GOT_ERR_NO_MEM);
	(*ref)->ref.ref.name = ref_name;
	memcpy(&(*ref)->ref.ref.sha1, digest, SHA1_DIGEST_LENGTH);
	return NULL;
}

static const struct got_error *
parse_ref_file(struct got_reference **ref, const char *name,
    const char *abspath)
{
	const struct got_error *err = NULL;
	FILE *f = fopen(abspath, "rb");
	char *line;
	size_t len;
	const char delim[3] = {'\0', '\0', '\0'};

	if (f == NULL)
		return got_error(GOT_ERR_NOT_REF);

	line = fparseln(f, &len, NULL, delim, 0);
	if (line == NULL) {
		err = got_error(GOT_ERR_NOT_REF);
		goto done;
	}

	err = parse_ref_line(ref, name, line);
done:
	free(line);
	fclose(f);
	return err;
}

static char *
get_refs_dir_path(struct got_repository *repo, const char *refname)
{
	if (strcmp(refname, GOT_REF_HEAD) == 0 ||
	    strcmp(refname, GOT_REF_ORIG_HEAD) == 0 ||
	    strcmp(refname, GOT_REF_MERGE_HEAD) == 0 ||
	    strcmp(refname, GOT_REF_FETCH_HEAD) == 0 ||
	    strncmp(refname, "refs/", 5) == 0)
		return got_repo_get_path_git_dir(repo);

	return got_repo_get_path_refs(repo);
}

const struct got_error *
got_ref_open(struct got_reference **ref, struct got_repository *repo,
   const char *refname)
{
	const struct got_error *err = NULL;
	char *path_ref = NULL;
	char *normpath = NULL;
	const char *parent_dir;
	char *path_refs = get_refs_dir_path(repo, refname);

	if (path_refs == NULL) {
		err = got_error(GOT_ERR_NO_MEM);
		goto done;
	}
	
	/* XXX For now, this assumes that refs exist in the filesystem. */

	if (asprintf(&path_ref, "%s/%s", path_refs, refname) == -1) {
		err = got_error(GOT_ERR_NO_MEM);
		goto done;
	}

	normpath = got_path_normalize(path_ref);
	if (normpath == NULL) {
		err = got_error(GOT_ERR_NOT_REF);
		goto done;
	}

	err = parse_ref_file(ref, refname, normpath);
done:
	free(normpath);
	free(path_ref);
	free(path_refs);
	return err;
}

void
got_ref_close(struct got_reference *ref)
{
	if (ref->flags & GOT_REF_IS_SYMBOLIC)
		free(ref->ref.symref.name);
	else
		free(ref->ref.ref.name);
	free(ref);
}

struct got_reference *
got_ref_dup(struct got_reference *ref)
{
	struct got_reference *ret;
	char *name = NULL;
	char *symref = NULL;

	ret = calloc(1, sizeof(*ret));
	if (ret == NULL)
		return NULL;

	ret->flags = ref->flags;
	if (ref->flags & GOT_REF_IS_SYMBOLIC) {
		ret->ref.symref.name = strdup(ref->ref.symref.name);
		if (ret->ref.symref.name == NULL) {
			free(ret);
			return NULL;
		}
		ret->ref.symref.ref = strdup(ref->ref.symref.ref);
		if (ret->ref.symref.ref == NULL) {
			free(ret->ref.symref.name);
			free(ret);
			return NULL;
		}
	} else {
		ref->ref.ref.name = strdup(ref->ref.ref.name);
		if (ref->ref.ref.name == NULL) {
			free(ret);
			return NULL;
		}
		memcpy(ret->ref.ref.sha1, ref->ref.ref.sha1,
		    SHA1_DIGEST_LENGTH);
	}

	return ret;
}

static const struct got_error *
resolve_symbolic_ref(struct got_reference **resolved,
    struct got_repository *repo, struct got_reference *ref)
{
	struct got_reference *nextref;
	const struct got_error *err;

	err = got_ref_open(&nextref, repo, ref->ref.symref.ref);
	if (err)
		return err;

	if (nextref->flags & GOT_REF_IS_SYMBOLIC)
		err = resolve_symbolic_ref(resolved, repo, nextref);
	else
		*resolved = got_ref_dup(nextref);

	got_ref_close(nextref);
	return err;
}

const struct got_error *
got_ref_resolve(struct got_object_id **id, struct got_repository *repo,
    struct got_reference *ref)
{
	const struct got_error *err;

	if (ref->flags & GOT_REF_IS_SYMBOLIC) {
		struct got_reference *resolved = NULL;
		err = resolve_symbolic_ref(&resolved, repo, ref);
		if (err == NULL)
			err = got_ref_resolve(id, repo, resolved);
		free(resolved);
		return err;
	}

	*id = calloc(1, sizeof(**id));
	if (*id == NULL)
		return got_error(GOT_ERR_NO_MEM);
	memcpy((*id)->sha1, ref->ref.ref.sha1, SHA1_DIGEST_LENGTH);
	return NULL;
}

char *
got_ref_to_str(struct got_reference *ref)
{
	char *str;
	if (ref->flags & GOT_REF_IS_SYMBOLIC) {
		if (asprintf(&str, "ref: %s", ref->ref.symref.ref) == -1)
			return NULL;
	} else {
		str = calloc(1, SHA1_DIGEST_STRING_LENGTH);
		if (str == NULL)
			return NULL;
		str = got_sha1_digest_to_str(ref->ref.ref.sha1, str,
		    SHA1_DIGEST_STRING_LENGTH);
	}

	return str;
}
