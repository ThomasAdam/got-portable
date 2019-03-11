/*
 * Copyright (c) 2018, 2019 Stefan Sperling <stsp@openbsd.org>
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
#include <sys/stat.h>

#include <errno.h>
#include <ctype.h>
#include <dirent.h>
#include <sha1.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <util.h>
#include <zlib.h>
#include <time.h>

#include "got_error.h"
#include "got_object.h"
#include "got_repository.h"
#include "got_reference.h"
#include "got_opentemp.h"

#include "got_lib_sha1.h"
#include "got_lib_path.h"
#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_lockfile.h"

#ifndef nitems
#define nitems(_a) (sizeof(_a) / sizeof((_a)[0]))
#endif

#define GOT_REF_HEADS	"heads"
#define GOT_REF_TAGS	"tags"
#define GOT_REF_REMOTES	"remotes"

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
		return got_error(GOT_ERR_BAD_REF_DATA);

	symref_name = strdup(name);
	if (symref_name == NULL)
		return got_error_from_errno();
	symref_ref = strdup(line);
	if (symref_ref == NULL) {
		const struct got_error *err = got_error_from_errno();
		free(symref_name);
		return err;
	}

	*ref = calloc(1, sizeof(**ref));
	if (*ref == NULL)
		return got_error_from_errno();
	(*ref)->flags |= GOT_REF_IS_SYMBOLIC;
	symref = &((*ref)->ref.symref);
	symref->name = symref_name;
	symref->ref = symref_ref;
	return NULL;
}

static const struct got_error *
parse_ref_line(struct got_reference **ref, const char *name, const char *line)
{
	struct got_object_id id;

	if (strncmp(line, "ref: ", 5) == 0) {
		line += 5;
		return parse_symref(ref, name, line);
	}

	if (!got_parse_sha1_digest(id.sha1, line))
		return got_error(GOT_ERR_BAD_REF_DATA);

	return got_ref_alloc(ref, name, &id);
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
		return NULL;

	line = fparseln(f, &len, NULL, delim, 0);
	if (line == NULL) {
		err = got_error(GOT_ERR_BAD_REF_DATA);
		goto done;
	}

	err = parse_ref_line(ref, name, line);
done:
	free(line);
	if (fclose(f) != 0 && err == NULL)
		err = got_error_from_errno();
	return err;
}

static int
is_well_known_ref(const char *refname)
{
	return (strcmp(refname, GOT_REF_HEAD) == 0 ||
	    strcmp(refname, GOT_REF_ORIG_HEAD) == 0 ||
	    strcmp(refname, GOT_REF_MERGE_HEAD) == 0 ||
	    strcmp(refname, GOT_REF_FETCH_HEAD) == 0);
}

static char *
get_refs_dir_path(struct got_repository *repo, const char *refname)
{
	if (is_well_known_ref(refname) || strncmp(refname, "refs/", 5) == 0)
		return strdup(got_repo_get_path_git_dir(repo));

	return got_repo_get_path_refs(repo);
}

static int
is_valid_ref_name(const char *name)
{
	const char *s, *slash, *seg;
	const char forbidden[] = { ' ', '~', '^', ':', '?', '*', '[' , '\\' };
	const char *forbidden_seq[] = { "//", "..", "@{" };
	const char *lfs = GOT_LOCKFILE_SUFFIX;
	const size_t lfs_len = sizeof(GOT_LOCKFILE_SUFFIX) - 1;
	int i;

	if (name[0] == '@' && name[1] == '\0')
		return 0;

	slash = strchr(name, '/');
	if (slash == NULL)
		return 0;

	s = name;
	seg = s;
	if (seg[0] == '\0' || seg[0] == '.' || seg[0] == '/')
		return 0;
	while (*s) {
		for (i = 0; i < nitems(forbidden); i++) {
			if (*s == forbidden[i])
				return 0;
		}
		for (i = 0; i < nitems(forbidden_seq); i++) {
			if (s[0] == forbidden_seq[i][0] &&
			    s[1] == forbidden_seq[i][1])
				return 0;
		}
		if (iscntrl((unsigned char)s[0]))
			return 0;
		if (s[0] == '.' && s[1] == '\0')
			return 0;
		if (*s == '/') {
			const char *nextseg = s + 1;
			if (nextseg[0] == '\0' || nextseg[0] == '.' ||
			    nextseg[0] == '/')
				return 0;
			if (seg <= s - lfs_len &&
			    strncmp(s - lfs_len, lfs, lfs_len) == 0)
				return 0;
			seg = nextseg;
		}
		s++;
	}

	if (seg <= s - lfs_len &&
	    strncmp(s - lfs_len, lfs, lfs_len) == 0)
		return 0;

	return 1;
}

const struct got_error *
got_ref_alloc(struct got_reference **ref, const char *name,
    struct got_object_id *id)
{
	const struct got_error *err = NULL;

	if (!is_valid_ref_name(name))
		return got_error(GOT_ERR_BAD_REF_NAME);

	*ref = calloc(1, sizeof(**ref));
	if (*ref == NULL)
		return got_error_from_errno();

	memcpy(&(*ref)->ref.ref.sha1, id->sha1, SHA1_DIGEST_LENGTH);
	(*ref)->ref.ref.name = strdup(name);
	if ((*ref)->ref.ref.name == NULL) {
		err = got_error_from_errno();
		free(*ref);
		*ref = NULL;
	}
	return err;
}

static const struct got_error *
parse_packed_ref_line(struct got_reference **ref, const char *abs_refname,
    const char *line)
{
	struct got_object_id id;
	const char *name;

	*ref = NULL;

	if (line[0] == '#' || line[0] == '^')
		return NULL;

	if (!got_parse_sha1_digest(id.sha1, line))
		return got_error(GOT_ERR_BAD_REF_DATA);

	if (abs_refname) {
		if (strcmp(line + SHA1_DIGEST_STRING_LENGTH, abs_refname) != 0)
			return NULL;
		name = abs_refname;
	} else
		name = line + SHA1_DIGEST_STRING_LENGTH;

	return got_ref_alloc(ref, name, &id);
}

static const struct got_error *
open_packed_ref(struct got_reference **ref, FILE *f, const char **subdirs,
    int nsubdirs, const char *refname)
{
	const struct got_error *err = NULL;
	char *abs_refname;
	char *line;
	size_t len;
	const char delim[3] = {'\0', '\0', '\0'};
	int i, ref_is_absolute = (strncmp(refname, "refs/", 5) == 0);

	*ref = NULL;

	if (ref_is_absolute)
		abs_refname = (char *)refname;
	do {
		line = fparseln(f, &len, NULL, delim, 0);
		if (line == NULL)
			break;
		for (i = 0; i < nsubdirs; i++) {
			if (!ref_is_absolute &&
			    asprintf(&abs_refname, "refs/%s/%s", subdirs[i],
			    refname) == -1)
				return got_error_from_errno();
			err = parse_packed_ref_line(ref, abs_refname, line);
			if (!ref_is_absolute)
				free(abs_refname);
			if (err || *ref != NULL)
				break;
		}
		free(line);
		if (err)
			break;
	} while (*ref == NULL);

	return err;
}

static const struct got_error *
open_ref(struct got_reference **ref, const char *path_refs, const char *subdir,
    const char *name)
{
	const struct got_error *err = NULL;
	char *path = NULL;
	char *normpath = NULL;
	char *absname = NULL;
	int ref_is_absolute = (strncmp(name, "refs/", 5) == 0);
	int ref_is_well_known = is_well_known_ref(name);

	*ref = NULL;

	if (ref_is_absolute || ref_is_well_known) {
		if (asprintf(&path, "%s/%s", path_refs, name) == -1)
			return got_error_from_errno();
		absname = (char *)name;
	} else {
		if (asprintf(&path, "%s/%s%s%s", path_refs, subdir,
		    subdir[0] ? "/" : "", name) == -1)
			return got_error_from_errno();

		if (asprintf(&absname, "refs/%s%s%s",
		    subdir, subdir[0] ? "/" : "", name) == -1) {
			err = got_error_from_errno();
			goto done;
		}
	}

	normpath = got_path_normalize(path);
	if (normpath == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	err = parse_ref_file(ref, absname, normpath);
done:
	if (!ref_is_absolute && !ref_is_well_known)
		free(absname);
	free(path);
	free(normpath);
	return err;
}

const struct got_error *
got_ref_open(struct got_reference **ref, struct got_repository *repo,
   const char *refname)
{
	const struct got_error *err = NULL;
	char *path_refs = NULL;
	const char *subdirs[] = {
	    GOT_REF_HEADS, GOT_REF_TAGS, GOT_REF_REMOTES
	};
	int i, well_known = is_well_known_ref(refname);

	*ref = NULL;

	path_refs = get_refs_dir_path(repo, refname);
	if (path_refs == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	if (!well_known) {
		char *packed_refs_path;
		FILE *f;

		/* Search on-disk refs before packed refs! */
		for (i = 0; i < nitems(subdirs); i++) {
			err = open_ref(ref, path_refs, subdirs[i], refname);
			if (err || *ref)
				goto done;
		}

		packed_refs_path = got_repo_get_path_packed_refs(repo);
		if (packed_refs_path == NULL) {
			err = got_error_from_errno();
			goto done;
		}

		f = fopen(packed_refs_path, "rb");
		free(packed_refs_path);
		if (f != NULL) {
			err = open_packed_ref(ref, f, subdirs, nitems(subdirs),
			    refname);
			if (fclose(f) != 0 && err == NULL)
				err = got_error_from_errno();
			if (err || *ref)
				goto done;
		}
	}

	err = open_ref(ref, path_refs, "", refname);
	if (err)
		goto done;
done:
	if (*ref == NULL)
		err = got_error_not_ref(refname);
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
		return got_error_from_errno();
	memcpy((*id)->sha1, ref->ref.ref.sha1, SHA1_DIGEST_LENGTH);
	return NULL;
}

char *
got_ref_to_str(struct got_reference *ref)
{
	char *str;

	if (ref->flags & GOT_REF_IS_SYMBOLIC)
		return strdup(ref->ref.symref.ref);

	str = malloc(SHA1_DIGEST_STRING_LENGTH);
	if (str == NULL)
		return NULL;

	if (got_sha1_digest_to_str(ref->ref.ref.sha1, str,
	    SHA1_DIGEST_STRING_LENGTH) == NULL) {
		free(str);
		return NULL;
	}

	return str;
}

const char *
got_ref_get_name(struct got_reference *ref)
{
	if (ref->flags & GOT_REF_IS_SYMBOLIC)
		return ref->ref.symref.name;

	return ref->ref.ref.name;
}

static const struct got_error *
insert_ref(struct got_reflist_head *refs, struct got_reference *ref,
    struct got_repository *repo)
{
	const struct got_error *err;
	struct got_object_id *id;
	struct got_reflist_entry *new, *re, *prev;
	int cmp;

	err = got_ref_resolve(&id, repo, ref);
	if (err)
		return err;

	new = malloc(sizeof(*re));
	if (new == NULL) {
		free(id);
		return got_error_from_errno();
	}
	new->ref = ref;
	new->id = id;

	/*
	 * We must de-duplicate entries on insert because packed-refs may
	 * contain redundant entries. On-disk refs take precedence.
	 * This code assumes that on-disk revs are read before packed-refs.
	 * We're iterating the list anyway, so insert elements sorted by name.
	 */
	re = SIMPLEQ_FIRST(refs);
	while (re) {
		cmp = got_path_cmp(got_ref_get_name(re->ref),
		    got_ref_get_name(ref));
		if (cmp == 0) {
			free(ref); /* duplicate */
			return NULL;
		} else if (cmp > 0) {
			if (prev)
				SIMPLEQ_INSERT_AFTER(refs, prev, new, entry);
			else
				SIMPLEQ_INSERT_HEAD(refs, new, entry);
			return NULL;
		} else {
			prev = re;
			re = SIMPLEQ_NEXT(re, entry);
		}
	}

	SIMPLEQ_INSERT_TAIL(refs, new, entry);
	return NULL;
}

static const struct got_error *
gather_on_disk_refs(struct got_reflist_head *refs, const char *path_refs,
    const char *subdir, struct got_repository *repo)
{
	const struct got_error *err = NULL;
	DIR *d = NULL;
	char *path_subdir;

	if (asprintf(&path_subdir, "%s/%s", path_refs, subdir) == -1)
		return got_error_from_errno();

	d = opendir(path_subdir);
	if (d == NULL)
		goto done;

	while (1) {
		struct dirent *dent;
		struct got_reference *ref;
		char *child;

		dent = readdir(d);
		if (dent == NULL)
			break;

		if (strcmp(dent->d_name, ".") == 0 ||
		    strcmp(dent->d_name, "..") == 0)
			continue;

		switch (dent->d_type) {
		case DT_REG:
			err = open_ref(&ref, path_refs, subdir, dent->d_name);
			if (err)
				goto done;
			if (ref) {
				err = insert_ref(refs, ref, repo);
				if (err)
					goto done;
			}
			break;
		case DT_DIR:
			if (asprintf(&child, "%s%s%s", subdir,
			    subdir[0] == '\0' ? "" : "/", dent->d_name) == -1) {
				err = got_error_from_errno();
				break;
			}
			err = gather_on_disk_refs(refs, path_refs, child, repo);
			free(child);
			break;
		default:
			break;
		}
	}
done:
	if (d)
		closedir(d);
	free(path_subdir);
	return err;
}

const struct got_error *
got_ref_list(struct got_reflist_head *refs, struct got_repository *repo)
{
	const struct got_error *err;
	char *packed_refs_path, *path_refs = NULL;
	FILE *f = NULL;
	struct got_reference *ref;

	/* HEAD ref should always exist. */
	path_refs = get_refs_dir_path(repo, GOT_REF_HEAD);
	if (path_refs == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	err = open_ref(&ref, path_refs, "", GOT_REF_HEAD);
	if (err)
		goto done;
	err = insert_ref(refs, ref, repo);
	if (err)
		goto done;

	/* Gather on-disk refs before parsing packed-refs. */
	free(path_refs);
	path_refs = get_refs_dir_path(repo, "");
	if (path_refs == NULL) {
		err = got_error_from_errno();
		goto done;
	}
	err = gather_on_disk_refs(refs, path_refs, "", repo);
	if (err)
		goto done;

	/*
	 * The packed-refs file may contain redundant entries, in which
	 * case on-disk refs take precedence.
	 */
	packed_refs_path = got_repo_get_path_packed_refs(repo);
	if (packed_refs_path == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	f = fopen(packed_refs_path, "r");
	free(packed_refs_path);
	if (f) {
		char *line;
		size_t len;
		const char delim[3] = {'\0', '\0', '\0'};
		while (1) {
			line = fparseln(f, &len, NULL, delim, 0);
			if (line == NULL)
				break;
			err = parse_packed_ref_line(&ref, NULL, line);
			if (err)
				goto done;
			if (ref) {
				err = insert_ref(refs, ref, repo);
				if (err)
					goto done;
			}
		}
	}
done:
	free(path_refs);
	if (f && fclose(f) != 0 && err == NULL)
		err = got_error_from_errno();
	return err;
}

const struct got_error *
got_ref_write(struct got_reference *ref, struct got_repository *repo)
{
	const struct got_error *err = NULL, *unlock_err = NULL;
	const char *name = got_ref_get_name(ref);
	char *path_refs = NULL, *path = NULL, *tmppath = NULL;
	struct got_lockfile *lf = NULL;
	FILE *f = NULL;
	size_t n;
	struct stat sb;

	path_refs = get_refs_dir_path(repo, name);
	if (path_refs == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	if (asprintf(&path, "%s/%s", path_refs, name) == -1) {
		err = got_error_from_errno();
		goto done;
	}

	err = got_opentemp_named(&tmppath, &f, path);
	if (f == NULL) {
		err = got_error_from_errno();
		goto done;
	}

	if (ref->flags & GOT_REF_IS_SYMBOLIC) {
		n = fprintf(f, "ref: %s\n", ref->ref.symref.ref);
		if (n != strlen(ref->ref.symref.ref) + 6) {
			err = got_ferror(f, GOT_ERR_IO);
			goto done;
		}
	} else {
		char hex[SHA1_DIGEST_STRING_LENGTH];
		if (got_sha1_digest_to_str(ref->ref.ref.sha1, hex,
		    sizeof(hex)) == NULL) {
			err = got_error(GOT_ERR_BAD_REF_DATA);
			goto done;
		}
		n = fprintf(f, "%s\n", hex);
		if (n != sizeof(hex) + 1) {
			err = got_ferror(f, GOT_ERR_IO);
			goto done;
		}
	}

	err = got_lockfile_lock(&lf, path);
	if (err)
		goto done;

	/* XXX: check if old content matches our expectations? */

	if (stat(path, &sb) != 0 && errno != ENOENT) {
		err = got_error_from_errno();
		goto done;
	}

	if (rename(tmppath, path) != 0) {
		err = got_error_from_errno();
		goto done;
	}
	free(tmppath);
	tmppath = NULL;

	if (chmod(path, sb.st_mode) != 0) {
		err = got_error_from_errno();
		goto done;
	}
done:
	if (lf)
		unlock_err = got_lockfile_unlock(lf);
	if (f) {
		if (fclose(f) != 0 && err == NULL)
			err = got_error_from_errno();
	}
	free(path_refs);
	free(path);
	if (tmppath) {
		if (unlink(tmppath) != 0 && err == NULL)
			err = got_error_from_errno();
		free(tmppath);
	}
	return err ? err : unlock_err;
}
