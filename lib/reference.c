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
#include <libgen.h>

#include "got_error.h"
#include "got_object.h"
#include "got_repository.h"
#include "got_reference.h"
#include "got_opentemp.h"
#include "got_path.h"

#include "got_lib_sha1.h"
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

/*
 * We do not resolve tags yet, and don't yet care about sorting refs either,
 * so packed-refs files we write contain a minimal header which disables all
 * packed-refs "traits" supported by Git.
 */
#define GOT_PACKED_REFS_HEADER	"# pack-refs with:"

/* A symbolic reference. */
struct got_symref {
	char *name;
	char *ref;
};

#define GOT_REF_RECURSE_MAX	20

/* A non-symbolic reference (there is no better designation). */
struct got_ref {
	char *name;
	u_int8_t sha1[SHA1_DIGEST_LENGTH];
};

/* A reference which points to an arbitrary object. */
struct got_reference {
	unsigned int flags;
#define GOT_REF_IS_SYMBOLIC	0x01
#define GOT_REF_IS_PACKED	0x02

	union {
		struct got_ref ref;
		struct got_symref symref;
	} ref;

	struct got_lockfile *lf;
};

static const struct got_error *
alloc_ref(struct got_reference **ref, const char *name,
    struct got_object_id *id, int flags)
{
	const struct got_error *err = NULL;

	*ref = calloc(1, sizeof(**ref));
	if (*ref == NULL)
		return got_error_from_errno("calloc");

	memcpy((*ref)->ref.ref.sha1, id->sha1, sizeof((*ref)->ref.ref.sha1));
	(*ref)->flags = flags;
	(*ref)->ref.ref.name = strdup(name);
	if ((*ref)->ref.ref.name == NULL) {
		err = got_error_from_errno("strdup");
		got_ref_close(*ref);
		*ref = NULL;
	}
	return err;
}

static const struct got_error *
alloc_symref(struct got_reference **ref, const char *name,
    const char *target_ref, int flags)
{
	const struct got_error *err = NULL;

	*ref = calloc(1, sizeof(**ref));
	if (*ref == NULL)
		return got_error_from_errno("calloc");

	(*ref)->flags = GOT_REF_IS_SYMBOLIC | flags;
	(*ref)->ref.symref.name = strdup(name);
	if ((*ref)->ref.symref.name == NULL) {
		err = got_error_from_errno("strdup");
		got_ref_close(*ref);
		*ref = NULL;
		return err;
	}
	(*ref)->ref.symref.ref = strdup(target_ref);
	if ((*ref)->ref.symref.ref == NULL) {
		err = got_error_from_errno("strdup");
		got_ref_close(*ref);
		*ref = NULL;
	}
	return err;
}

static const struct got_error *
parse_symref(struct got_reference **ref, const char *name, const char *line)
{
	if (line[0] == '\0')
		return got_error(GOT_ERR_BAD_REF_DATA);

	return alloc_symref(ref, name, line, 0);
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

	return alloc_ref(ref, name, &id, 0);
}

static const struct got_error *
parse_ref_file(struct got_reference **ref, const char *name,
    const char *abspath, int lock)
{
	const struct got_error *err = NULL;
	FILE *f;
	char *line;
	size_t len;
	const char delim[3] = {'\0', '\0', '\0'};
	struct got_lockfile *lf = NULL;

	if (lock) {
		err = got_lockfile_lock(&lf, abspath);
		if (err)
			return (err);
	}

	f = fopen(abspath, "rb");
	if (f == NULL) {
		if (lock)
			got_lockfile_unlock(lf);
		return NULL;
	}

	line = fparseln(f, &len, NULL, delim, 0);
	if (line == NULL) {
		err = got_error(GOT_ERR_BAD_REF_DATA);
		if (lock)
			got_lockfile_unlock(lf);
		goto done;
	}

	err = parse_ref_line(ref, name, line);
	if (lock) {
		if (err)
			got_lockfile_unlock(lf);
		else {
			if (*ref)
				(*ref)->lf = lf;
			else
				got_lockfile_unlock(lf);
		}
	}
done:
	free(line);
	if (fclose(f) != 0 && err == NULL) {
		err = got_error_from_errno("fclose");
		if (*ref) {
			if (lock)
				got_ref_unlock(*ref);
			got_ref_close(*ref);
			*ref = NULL;
		}
	}
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
	if (!is_valid_ref_name(name))
		return got_error(GOT_ERR_BAD_REF_NAME);

	return alloc_ref(ref, name, id, 0);
}

const struct got_error *
got_ref_alloc_symref(struct got_reference **ref, const char *name,
	struct got_reference *target_ref)
{
	if (!is_valid_ref_name(name))
		return got_error(GOT_ERR_BAD_REF_NAME);

	return alloc_symref(ref, name, got_ref_get_name(target_ref), 0);
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

	return alloc_ref(ref, name, &id, GOT_REF_IS_PACKED);
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
		if (line == NULL) {
			if (feof(f))
				break;
			err = got_ferror(f, GOT_ERR_BAD_REF_DATA);
			break;
		}
		for (i = 0; i < nsubdirs; i++) {
			if (!ref_is_absolute &&
			    asprintf(&abs_refname, "refs/%s/%s", subdirs[i],
			    refname) == -1)
				return got_error_from_errno("asprintf");
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
    const char *name, int lock)
{
	const struct got_error *err = NULL;
	char *path = NULL;
	char *absname = NULL;
	int ref_is_absolute = (strncmp(name, "refs/", 5) == 0);
	int ref_is_well_known = is_well_known_ref(name);

	*ref = NULL;

	if (ref_is_absolute || ref_is_well_known) {
		if (asprintf(&path, "%s/%s", path_refs, name) == -1)
			return got_error_from_errno("asprintf");
		absname = (char *)name;
	} else {
		if (asprintf(&path, "%s/%s%s%s", path_refs, subdir,
		    subdir[0] ? "/" : "", name) == -1)
			return got_error_from_errno("asprintf");

		if (asprintf(&absname, "refs/%s%s%s",
		    subdir, subdir[0] ? "/" : "", name) == -1) {
			err = got_error_from_errno("asprintf");
			goto done;
		}
	}

	err = parse_ref_file(ref, absname, path, lock);
done:
	if (!ref_is_absolute && !ref_is_well_known)
		free(absname);
	free(path);
	return err;
}

const struct got_error *
got_ref_open(struct got_reference **ref, struct got_repository *repo,
   const char *refname, int lock)
{
	const struct got_error *err = NULL;
	char *path_refs = NULL;
	const char *subdirs[] = {
	    GOT_REF_HEADS, GOT_REF_TAGS, GOT_REF_REMOTES
	};
	int i, well_known = is_well_known_ref(refname);
	struct got_lockfile *lf = NULL;

	*ref = NULL;

	path_refs = get_refs_dir_path(repo, refname);
	if (path_refs == NULL) {
		err = got_error_from_errno2("get_refs_dir_path", refname);
		goto done;
	}

	if (well_known) {
		err = open_ref(ref, path_refs, "", refname, lock);
	} else {
		char *packed_refs_path;
		FILE *f;

		/* Search on-disk refs before packed refs! */
		for (i = 0; i < nitems(subdirs); i++) {
			err = open_ref(ref, path_refs, subdirs[i], refname,
			    lock);
			if (err || *ref)
				goto done;
		}

		packed_refs_path = got_repo_get_path_packed_refs(repo);
		if (packed_refs_path == NULL) {
			err = got_error_from_errno(
			    "got_repo_get_path_packed_refs");
			goto done;
		}

		if (lock) {
			err = got_lockfile_lock(&lf, packed_refs_path);
			if (err)
				goto done;
		}
		f = fopen(packed_refs_path, "rb");
		free(packed_refs_path);
		if (f != NULL) {
			err = open_packed_ref(ref, f, subdirs, nitems(subdirs),
			    refname);
			if (!err) {
				if (fclose(f) != 0) {
					err = got_error_from_errno("fclose");
					got_ref_close(*ref);
					*ref = NULL;
				} else if (*ref)
					(*ref)->lf = lf;
			}
		}
	}
done:
	if (!err && *ref == NULL)
		err = got_error_not_ref(refname);
	if (err && lf)
		got_lockfile_unlock(lf);
	free(path_refs);
	return err;
}

void
got_ref_close(struct got_reference *ref)
{
	if (ref->flags & GOT_REF_IS_SYMBOLIC) {
		free(ref->ref.symref.name);
		free(ref->ref.symref.ref);
	} else
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
		    sizeof(ret->ref.ref.sha1));
	}

	return ret;
}

const struct got_error *
got_reflist_entry_dup(struct got_reflist_entry **newp,
    struct got_reflist_entry *re)
{
	const struct got_error *err = NULL;
	struct got_reflist_entry *new;

	*newp = NULL;

	new = malloc(sizeof(*new));
	if (new == NULL)
		return got_error_from_errno("malloc");

	new->ref = got_ref_dup(re->ref);
	if (new->ref == NULL) {
		err = got_error_from_errno("got_ref_dup");
		free(new);
		return err;
	}

	new->id = got_object_id_dup(re->id);
	if (new->id == NULL) {
		err = got_error_from_errno("got_ref_dup");
		free(new->id);
		free(new);
		return err;
	}

	*newp = new;
	return NULL;
}

static const struct got_error *
resolve_symbolic_ref(struct got_reference **resolved,
    struct got_repository *repo, struct got_reference *ref)
{
	struct got_reference *nextref;
	const struct got_error *err;

	err = got_ref_open(&nextref, repo, ref->ref.symref.ref, 0);
	if (err)
		return err;

	if (nextref->flags & GOT_REF_IS_SYMBOLIC)
		err = resolve_symbolic_ref(resolved, repo, nextref);
	else
		*resolved = got_ref_dup(nextref);

	got_ref_close(nextref);
	return err;
}

static const struct got_error *
ref_resolve(struct got_object_id **id, struct got_repository *repo,
    struct got_reference *ref, int recursion)
{
	const struct got_error *err;

	if (recursion <= 0)
		return got_error_msg(GOT_ERR_RECURSION,
		    "reference recursion limit reached");

	if (ref->flags & GOT_REF_IS_SYMBOLIC) {
		struct got_reference *resolved = NULL;
		err = resolve_symbolic_ref(&resolved, repo, ref);
		if (err == NULL)
			err = ref_resolve(id, repo, resolved, --recursion);
		if (resolved)
			got_ref_close(resolved);
		return err;
	}

	*id = calloc(1, sizeof(**id));
	if (*id == NULL)
		return got_error_from_errno("calloc");
	memcpy((*id)->sha1, ref->ref.ref.sha1, sizeof((*id)->sha1));
	return NULL;
}

const struct got_error *
got_ref_resolve(struct got_object_id **id, struct got_repository *repo,
    struct got_reference *ref)
{
	return ref_resolve(id, repo, ref, GOT_REF_RECURSE_MAX);
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

const char *
got_ref_get_symref_target(struct got_reference *ref)
{
	if (ref->flags & GOT_REF_IS_SYMBOLIC)
		return ref->ref.symref.ref;

	return NULL;
}

const struct got_error *
got_ref_cmp_by_name(void *arg, int *cmp, struct got_reference *re1,
    struct got_reference* re2)
{
	const char *name1 = got_ref_get_name(re1);
	const char *name2 = got_ref_get_name(re2);

	*cmp = got_path_cmp(name1, name2, strlen(name1), strlen(name2));
	return NULL;
}

static const struct got_error *
insert_ref(struct got_reflist_entry **newp, struct got_reflist_head *refs,
    struct got_reference *ref, struct got_repository *repo,
    got_ref_cmp_cb cmp_cb, void *cmp_arg)
{
	const struct got_error *err;
	struct got_object_id *id;
	struct got_reflist_entry *new, *re, *prev = NULL;
	int cmp;

	*newp = NULL;

	err = got_ref_resolve(&id, repo, ref);
	if (err)
		return err;

	new = malloc(sizeof(*new));
	if (new == NULL) {
		free(id);
		return got_error_from_errno("malloc");
	}
	new->ref = ref;
	new->id = id;
	*newp = new;

	/*
	 * We must de-duplicate entries on insert because packed-refs may
	 * contain redundant entries. On-disk refs take precedence.
	 * This code assumes that on-disk revs are read before packed-refs.
	 * We're iterating the list anyway, so insert elements sorted by name.
	 */
	re = SIMPLEQ_FIRST(refs);
	while (re) {
		err = (*cmp_cb)(cmp_arg, &cmp, re->ref, new->ref);
		if (err)
			return err;
		if (cmp == 0) {
			/* duplicate */
			free(new->id);
			free(new);
			*newp = NULL;
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
    const char *subdir, struct got_repository *repo,
    got_ref_cmp_cb cmp_cb, void *cmp_arg)
{
	const struct got_error *err = NULL;
	DIR *d = NULL;
	char *path_subdir;

	if (asprintf(&path_subdir, "%s/%s", path_refs, subdir) == -1)
		return got_error_from_errno("asprintf");

	d = opendir(path_subdir);
	if (d == NULL)
		goto done;

	for (;;) {
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
			err = open_ref(&ref, path_refs, subdir, dent->d_name,
			    0);
			if (err)
				goto done;
			if (ref) {
				struct got_reflist_entry *new;
				err = insert_ref(&new, refs, ref, repo,
				    cmp_cb, cmp_arg);
				if (err || new == NULL /* duplicate */)
					got_ref_close(ref);
				if (err)
					goto done;
			}
			break;
		case DT_DIR:
			if (asprintf(&child, "%s%s%s", subdir,
			    subdir[0] == '\0' ? "" : "/", dent->d_name) == -1) {
				err = got_error_from_errno("asprintf");
				break;
			}
			err = gather_on_disk_refs(refs, path_refs, child, repo,
			    cmp_cb, cmp_arg);
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
got_ref_list(struct got_reflist_head *refs, struct got_repository *repo,
    const char *ref_namespace, got_ref_cmp_cb cmp_cb, void *cmp_arg)
{
	const struct got_error *err;
	char *packed_refs_path, *path_refs = NULL;
	const char *ondisk_ref_namespace = NULL;
	FILE *f = NULL;
	struct got_reference *ref;
	struct got_reflist_entry *new;

	if (ref_namespace == NULL || ref_namespace[0] == '\0') {
		/* HEAD ref should always exist. */
		path_refs = get_refs_dir_path(repo, GOT_REF_HEAD);
		if (path_refs == NULL) {
			err = got_error_from_errno("get_refs_dir_path");
			goto done;
		}
		err = open_ref(&ref, path_refs, "", GOT_REF_HEAD, 0);
		if (err)
			goto done;
		err = insert_ref(&new, refs, ref, repo, cmp_cb, cmp_arg);
		if (err || new == NULL /* duplicate */)
			got_ref_close(ref);
		if (err)
			goto done;
	}

	ondisk_ref_namespace = ref_namespace;
	if (ref_namespace && strncmp(ref_namespace, "refs/", 5) == 0)
		ondisk_ref_namespace += 5;

	/* Gather on-disk refs before parsing packed-refs. */
	free(path_refs);
	path_refs = get_refs_dir_path(repo, "");
	if (path_refs == NULL) {
		err = got_error_from_errno("get_refs_dir_path");
		goto done;
	}
	err = gather_on_disk_refs(refs, path_refs,
	    ondisk_ref_namespace ? ondisk_ref_namespace : "", repo,
	    cmp_cb, cmp_arg);
	if (err)
		goto done;

	/*
	 * The packed-refs file may contain redundant entries, in which
	 * case on-disk refs take precedence.
	 */
	packed_refs_path = got_repo_get_path_packed_refs(repo);
	if (packed_refs_path == NULL) {
		err = got_error_from_errno("got_repo_get_path_packed_refs");
		goto done;
	}

	f = fopen(packed_refs_path, "r");
	free(packed_refs_path);
	if (f) {
		char *line;
		size_t len;
		const char delim[3] = {'\0', '\0', '\0'};
		for (;;) {
			line = fparseln(f, &len, NULL, delim, 0);
			if (line == NULL) {
				if (feof(f))
					break;
				err = got_ferror(f, GOT_ERR_BAD_REF_DATA);
				goto done;
			}
			err = parse_packed_ref_line(&ref, NULL, line);
			free(line);
			if (err)
				goto done;
			if (ref) {
				if (ref_namespace) {
					const char *name;
					name = got_ref_get_name(ref);
					if (strncmp(name, ref_namespace,
					    strlen(ref_namespace)) != 0) {
						got_ref_close(ref);
						continue;
					}
				}
				err = insert_ref(&new, refs, ref, repo,
				    cmp_cb, cmp_arg);
				if (err || new == NULL /* duplicate */)
					got_ref_close(ref);
				if (err)
					goto done;
			}
		}
	}
done:
	free(path_refs);
	if (f && fclose(f) != 0 && err == NULL)
		err = got_error_from_errno("fclose");
	return err;
}

void
got_ref_list_free(struct got_reflist_head *refs)
{
	struct got_reflist_entry *re;

	while (!SIMPLEQ_EMPTY(refs)) {
		re = SIMPLEQ_FIRST(refs);
		SIMPLEQ_REMOVE_HEAD(refs, entry);
		got_ref_close(re->ref);
		free(re->id);
		free(re);
	}

}

int
got_ref_is_symbolic(struct got_reference *ref)
{
	return (ref->flags & GOT_REF_IS_SYMBOLIC);
}

const struct got_error *
got_ref_change_ref(struct got_reference *ref, struct got_object_id *id)
{
	if (ref->flags & GOT_REF_IS_SYMBOLIC)
		return got_error(GOT_ERR_BAD_REF_TYPE);

	memcpy(ref->ref.ref.sha1, id->sha1, sizeof(ref->ref.ref.sha1));
	return NULL;
}

const struct got_error *
got_ref_change_symref(struct got_reference *ref, char *refname)
{
	char *new_name;

	if ((ref->flags & GOT_REF_IS_SYMBOLIC) == 0)
		return got_error(GOT_ERR_BAD_REF_TYPE);

	new_name = strdup(refname);
	if (new_name == NULL)
		return got_error_from_errno("strdup");

	free(ref->ref.symref.name);
	ref->ref.symref.name = new_name;
	return NULL;
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
		err = got_error_from_errno2("get_refs_dir_path", name);
		goto done;
	}

	if (asprintf(&path, "%s/%s", path_refs, name) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	err = got_opentemp_named(&tmppath, &f, path);
	if (err) {
		char *parent;
		if (!(err->code == GOT_ERR_ERRNO && errno == ENOENT))
			goto done;
		err = got_path_dirname(&parent, path);
		if (err)
			goto done;
		err = got_path_mkdir(parent);
		free(parent);
		if (err)
			goto done;
		err = got_opentemp_named(&tmppath, &f, path);
		if (err)
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
		if (n != sizeof(hex)) {
			err = got_ferror(f, GOT_ERR_IO);
			goto done;
		}
	}

	if (ref->lf == NULL) {
		err = got_lockfile_lock(&lf, path);
		if (err)
			goto done;
	}

	/* XXX: check if old content matches our expectations? */

	if (stat(path, &sb) != 0) {
		if (errno != ENOENT) {
			err = got_error_from_errno2("stat", path);
			goto done;
		}
		sb.st_mode = GOT_DEFAULT_FILE_MODE;
	}

	if (rename(tmppath, path) != 0) {
		err = got_error_from_errno3("rename", tmppath, path);
		goto done;
	}
	free(tmppath);
	tmppath = NULL;

	if (chmod(path, sb.st_mode) != 0) {
		err = got_error_from_errno2("chmod", path);
		goto done;
	}
done:
	if (ref->lf == NULL && lf)
		unlock_err = got_lockfile_unlock(lf);
	if (f) {
		if (fclose(f) != 0 && err == NULL)
			err = got_error_from_errno("fclose");
	}
	free(path_refs);
	free(path);
	if (tmppath) {
		if (unlink(tmppath) != 0 && err == NULL)
			err = got_error_from_errno2("unlink", tmppath);
		free(tmppath);
	}
	return err ? err : unlock_err;
}

static const struct got_error *
delete_packed_ref(struct got_reference *delref, struct got_repository *repo)
{
	const struct got_error *err = NULL, *unlock_err = NULL;
	struct got_lockfile *lf = NULL;
	FILE *f = NULL, *tmpf = NULL;
	char *packed_refs_path, *tmppath = NULL;
	struct got_reflist_head refs;
	int found_delref = 0;

	/* The packed-refs file does not cotain symbolic references. */
	if (delref->flags & GOT_REF_IS_SYMBOLIC)
		return got_error(GOT_ERR_BAD_REF_DATA);

	SIMPLEQ_INIT(&refs);

	packed_refs_path = got_repo_get_path_packed_refs(repo);
	if (packed_refs_path == NULL)
		return got_error_from_errno("got_repo_get_path_packed_refs");

	err = got_opentemp_named(&tmppath, &tmpf, packed_refs_path);
	if (err)
		goto done;

	if (delref->lf == NULL) {
		err = got_lockfile_lock(&lf, packed_refs_path);
		if (err)
			goto done;
	}

	f = fopen(packed_refs_path, "r");
	if (f == NULL) {
		err = got_error_from_errno2("fopen", packed_refs_path);
		goto done;
	}
	for (;;) {
		char *line;
		size_t len;
		const char delim[3] = {'\0', '\0', '\0'};
		struct got_reference *ref;
		struct got_reflist_entry *new;

		line = fparseln(f, &len, NULL, delim, 0);
		if (line == NULL) {
			if (feof(f))
				break;
			err = got_ferror(f, GOT_ERR_BAD_REF_DATA);
			goto done;
		}
		err = parse_packed_ref_line(&ref, NULL, line);
		free(line);
		if (err)
			goto done;
		if (ref == NULL)
			continue;

		if (strcmp(ref->ref.ref.name, delref->ref.ref.name) == 0 &&
		    memcmp(ref->ref.ref.sha1, delref->ref.ref.sha1,
		    sizeof(delref->ref.ref.sha1)) == 0) {
			found_delref = 1;
			got_ref_close(ref);
			continue;
		}

		err = insert_ref(&new, &refs, ref, repo,
		    got_ref_cmp_by_name, NULL);
		if (err || new == NULL /* duplicate */)
			got_ref_close(ref);
		if (err)
			goto done;
	}

	if (found_delref) {
		struct got_reflist_entry *re;
		size_t n;
		struct stat sb;

		n = fprintf(tmpf, "%s\n", GOT_PACKED_REFS_HEADER);
		if (n != sizeof(GOT_PACKED_REFS_HEADER)) {
			err = got_ferror(f, GOT_ERR_IO);
			goto done;
		}

		SIMPLEQ_FOREACH(re, &refs, entry) {
			uint8_t hex[SHA1_DIGEST_STRING_LENGTH];

			if (got_sha1_digest_to_str(re->ref->ref.ref.sha1, hex,
			    sizeof(hex)) == NULL) {
				err = got_error(GOT_ERR_BAD_REF_DATA);
				goto done;
			}
			n = fprintf(tmpf, "%s ", hex);
			if (n != sizeof(hex)) {
				err = got_ferror(f, GOT_ERR_IO);
				goto done;
			}
			n = fprintf(tmpf, "%s\n", re->ref->ref.ref.name);
			if (n != strlen(re->ref->ref.ref.name) + 1) {
				err = got_ferror(f, GOT_ERR_IO);
				goto done;
			}
		}

		if (fflush(tmpf) != 0) {
			err = got_error_from_errno("fflush");
			goto done;
		}

		if (stat(packed_refs_path, &sb) != 0) {
			if (errno != ENOENT) {
				err = got_error_from_errno2("stat",
				    packed_refs_path);
				goto done;
			}
			sb.st_mode = GOT_DEFAULT_FILE_MODE;
		}

		if (rename(tmppath, packed_refs_path) != 0) {
			err = got_error_from_errno3("rename", tmppath,
			    packed_refs_path);
			goto done;
		}

		if (chmod(packed_refs_path, sb.st_mode) != 0) {
			err = got_error_from_errno2("chmod",
			    packed_refs_path);
			goto done;
		}
	}
done:
	if (delref->lf == NULL && lf)
		unlock_err = got_lockfile_unlock(lf);
	if (f) {
		if (fclose(f) != 0 && err == NULL)
			err = got_error_from_errno("fclose");
	}
	if (tmpf) {
		unlink(tmppath);
		if (fclose(tmpf) != 0 && err == NULL)
			err = got_error_from_errno("fclose");
	}
	free(tmppath);
	free(packed_refs_path);
	got_ref_list_free(&refs);
	return err ? err : unlock_err;
}

const struct got_error *
got_ref_delete(struct got_reference *ref, struct got_repository *repo)
{
	const struct got_error *err = NULL, *unlock_err = NULL;
	const char *name = got_ref_get_name(ref);
	char *path_refs = NULL, *path = NULL;
	struct got_lockfile *lf = NULL;

	if (ref->flags & GOT_REF_IS_PACKED)
		return delete_packed_ref(ref, repo);

	path_refs = get_refs_dir_path(repo, name);
	if (path_refs == NULL) {
		err = got_error_from_errno2("get_refs_dir_path", name);
		goto done;
	}

	if (asprintf(&path, "%s/%s", path_refs, name) == -1) {
		err = got_error_from_errno("asprintf");
		goto done;
	}

	if (ref->lf == NULL) {
		err = got_lockfile_lock(&lf, path);
		if (err)
			goto done;
	}

	/* XXX: check if old content matches our expectations? */

	if (unlink(path) != 0)
		err = got_error_from_errno2("unlink", path);
done:
	if (ref->lf == NULL && lf)
		unlock_err = got_lockfile_unlock(lf);

	free(path_refs);
	free(path);
	return err ? err : unlock_err;
}

const struct got_error *
got_ref_unlock(struct got_reference *ref)
{
	const struct got_error *err;
	err = got_lockfile_unlock(ref->lf);
	ref->lf = NULL;
	return err;
}
