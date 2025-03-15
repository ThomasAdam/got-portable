/*
 * Copyright (c) 2019, 2025 Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2022 Mark Jamsek <mark@jamsek.dev>
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

#include "got_compat.h"

#include <sys/time.h>
#include <sys/queue.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include "got_error.h"
#include "got_path.h"
#include "got_object.h"
#include "got_repository.h"

#include "got_lib_hash.h"
#include "got_lib_delta.h"
#include "got_lib_object.h"
#include "got_lib_object_cache.h"
#include "got_lib_pack.h"
#include "got_lib_repository.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

const struct got_error *
got_repo_init(const char *repo_path, const char *head_name,
    enum got_hash_algorithm algo)
{
	const struct got_error *err = NULL;
	const char *dirnames[] = {
		GOT_OBJECTS_DIR,
		GOT_OBJECTS_PACK_DIR,
		GOT_REFS_DIR,
	};
	const char *description_str = "Unnamed repository; "
	    "edit this file 'description' to name the repository.";
	const char *headref = "ref: refs/heads/";
	const char *gitconfig_sha1 = "[core]\n"
	    "\trepositoryformatversion = 0\n"
	    "\tfilemode = true\n"
	    "\tbare = true\n";
	const char *gitconfig_sha256 = "[core]\n"
	    "\trepositoryformatversion = 1\n"
	    "\tfilemode = true\n"
	    "\tbare = true\n"
	    "[extensions]\n"
	    "\tobjectformat = sha256\n";
	const char *gitconfig = gitconfig_sha1;
	char *headref_str, *path;
	size_t i;

	if (algo == GOT_HASH_SHA256)
		gitconfig = gitconfig_sha256;

	if (!got_path_dir_is_empty(repo_path))
		return got_error(GOT_ERR_DIR_NOT_EMPTY);

	for (i = 0; i < nitems(dirnames); i++) {
		if (asprintf(&path, "%s/%s", repo_path, dirnames[i]) == -1) {
			return got_error_from_errno("asprintf");
		}
		err = got_path_mkdir(path);
		free(path);
		if (err)
			return err;
	}

	if (asprintf(&path, "%s/%s", repo_path, "description") == -1)
		return got_error_from_errno("asprintf");
	err = got_path_create_file(path, description_str);
	free(path);
	if (err)
		return err;

	if (asprintf(&path, "%s/%s", repo_path, GOT_HEAD_FILE) == -1)
		return got_error_from_errno("asprintf");
	if (asprintf(&headref_str, "%s%s", headref,
	    head_name ? head_name : "main") == -1) {
		free(path);
		return got_error_from_errno("asprintf");
	}
	err = got_path_create_file(path, headref_str);
	free(headref_str);
	free(path);
	if (err)
		return err;

	if (asprintf(&path, "%s/%s", repo_path, "config") == -1)
		return got_error_from_errno("asprintf");
	err = got_path_create_file(path, gitconfig);
	free(path);
	if (err)
		return err;

	return NULL;
}
