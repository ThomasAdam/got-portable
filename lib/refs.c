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
#include <sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <util.h>

#include "got_error.h"
#include "got_refs.h"

#include "path.h"

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
	(*ref)->flags |= GOT_REF_IS_SYMBOLIC;
	symref = &((*ref)->ref.symref);
	symref->name = symref_name;
	symref->ref = symref_ref;
	return NULL;
}

static int
parse_sha1_digest(uint8_t *digest, const char *line)
{
	uint8_t b;
	int i, n;

	for (i = 0; i < SHA1_DIGEST_LENGTH; i++) {
		n = sscanf(line, "%hhx", &b);
		if (n == 1)
			digest[i] = b;
		else
			return 0;
	}

	return 1;
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

	if (!parse_sha1_digest(digest, line))
		return got_error(GOT_ERR_NOT_REF);

	*ref = calloc(1, sizeof(**ref));
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

const struct got_error *
got_ref_open(struct got_reference **ref, const char *path_refs,
   const char *refname)
{
	const struct got_error *err = NULL;
	char *path_ref = NULL;
	char *normpath = NULL;
	const char *parent_dir;
	
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

	err = parse_ref_file(ref, refname, normpath ? normpath : path_refs);
done:
	free(normpath);
	free(path_ref);
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
