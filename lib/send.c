/*
 * Copyright (c) 2018, 2019 Ori Bernstein <ori@openbsd.org>
 * Copyright (c) 2021 Stefan Sperling <stsp@openbsd.org>
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
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/socket.h>

#include <errno.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <zlib.h>
#include <ctype.h>
#include <limits.h>
#include <time.h>

#include "got_error.h"
#include "got_reference.h"
#include "got_repository.h"
#include "got_path.h"
#include "got_cancel.h"
#include "got_worktree.h"
#include "got_object.h"
#include "got_opentemp.h"
#include "got_send.h"
#include "got_repository_admin.h"
#include "got_commit_graph.h"

#include "got_lib_delta.h"
#include "got_lib_inflate.h"
#include "got_lib_object.h"
#include "got_lib_object_parse.h"
#include "got_lib_object_create.h"
#include "got_lib_pack.h"
#include "got_lib_hash.h"
#include "got_lib_privsep.h"
#include "got_lib_object_cache.h"
#include "got_lib_repository.h"
#include "got_lib_ratelimit.h"
#include "got_lib_pack_create.h"
#include "got_lib_dial.h"

#ifndef nitems
#define nitems(_a)	(sizeof((_a)) / sizeof((_a)[0]))
#endif

#ifndef ssizeof
#define ssizeof(_x) ((ssize_t)(sizeof(_x)))
#endif

#ifndef MIN
#define	MIN(_a,_b) ((_a) < (_b) ? (_a) : (_b))
#endif

const struct got_error *
got_send_connect(pid_t *sendpid, int *sendfd, const char *proto,
    const char *host, const char *port, const char *server_path, int verbosity)
{
	const struct got_error *err = NULL;

	*sendpid = -1;
	*sendfd = -1;

	if (strcmp(proto, "ssh") == 0 || strcmp(proto, "git+ssh") == 0)
		err = got_dial_ssh(sendpid, sendfd, host, port, server_path,
		    GOT_DIAL_DIRECTION_SEND, verbosity);
	else if (strcmp(proto, "git") == 0)
		err = got_dial_git(sendfd, host, port, server_path,
		    GOT_DIAL_DIRECTION_SEND);
	else if (strcmp(proto, "http") == 0 || strcmp(proto, "git+http") == 0)
		err = got_error_path(proto, GOT_ERR_NOT_IMPL);
	else
		err = got_error_path(proto, GOT_ERR_BAD_PROTO);
	return err;
}

struct pack_progress_arg {
    got_send_progress_cb progress_cb;
    void *progress_arg;

    int ncolored;
    int nfound;
    int ntrees;
    off_t packfile_size;
    int ncommits;
    int nobj_total;
    int nobj_deltify;
    int nobj_written;
};

static const struct got_error *
pack_progress(void *arg, int ncolored, int nfound, int ntrees,
    off_t packfile_size, int ncommits, int nobj_total, int nobj_deltify,
    int nobj_written)
{
	const struct got_error *err;
	struct pack_progress_arg *a = arg;

	err = a->progress_cb(a->progress_arg, ncolored, nfound, ntrees,
	    packfile_size, ncommits, nobj_total, nobj_deltify,
	    nobj_written, 0, NULL, NULL, 0);
	if (err)
		return err;

	a->ncolored= ncolored;
	a->nfound = nfound;
	a->ntrees = ntrees;
	a->packfile_size = packfile_size;
	a->ncommits = ncommits;
	a->nobj_total = nobj_total;
	a->nobj_deltify = nobj_deltify;
	a->nobj_written = nobj_written;
	return NULL;
}

static const struct got_error *
insert_ref(struct got_reflist_head *refs, const char *refname,
    struct got_repository *repo)
{
	const struct got_error *err;
	struct got_reference *ref;
	struct got_reflist_entry *new;

	err = got_ref_open(&ref, repo, refname, 0);
	if (err)
		return err;

	err = got_reflist_insert(&new, refs, ref, got_ref_cmp_by_name, NULL);
	if (err || new == NULL /* duplicate */)
		got_ref_close(ref);

	return err;
}

static const struct got_error *
check_linear_ancestry(const char *refname, struct got_object_id *my_id,
    struct got_object_id *their_id, struct got_repository *repo,
    got_cancel_cb cancel_cb, void *cancel_arg)
{
	const struct got_error *err = NULL;
	struct got_object_id *yca_id;
	int obj_type;

	err = got_object_get_type(&obj_type, repo, their_id);
	if (err)
		return err;
	if (obj_type != GOT_OBJ_TYPE_COMMIT)
		return got_error_fmt(GOT_ERR_OBJ_TYPE,
		    "bad object type on server for %s", refname);

	err = got_commit_graph_find_youngest_common_ancestor(&yca_id,
	    my_id, their_id, 1, repo, cancel_cb, cancel_arg);
	if (err)
		return err;
	if (yca_id == NULL)
		return got_error_fmt(GOT_ERR_SEND_ANCESTRY, "%s", refname);

	/*
	 * Require a straight line of history between the two commits,
	 * with their commit being older than my commit.
	 *
	 * Non-linear situations such as this require a rebase:
	 *
	 * (theirs) D       F (mine)
	 *           \     /
	 *            C   E
	 *             \ /
	 *              B (yca)
	 *              |
	 *              A
	 */
	if (got_object_id_cmp(their_id, yca_id) != 0)
		err = got_error_fmt(GOT_ERR_SEND_ANCESTRY, "%s", refname);

	free(yca_id);
	return err;
}

static const struct got_error *
realloc_ids(struct got_object_id ***ids, size_t *nalloc, size_t n)
{
	struct got_object_id **new;
	const size_t alloc_chunksz = 256;

	if (*nalloc >= n)
		return NULL;

	new = recallocarray(*ids, *nalloc, *nalloc + alloc_chunksz,
	    sizeof(struct got_object_id));
	if (new == NULL)
		return got_error_from_errno("recallocarray");

	*ids = new;
	*nalloc += alloc_chunksz;
	return NULL;
}

static struct got_reference *
find_ref(struct got_reflist_head *refs, const char *refname)
{
	struct got_reflist_entry *re;

	TAILQ_FOREACH(re, refs, entry) {
		if (got_path_cmp(got_ref_get_name(re->ref), refname,
		    strlen(got_ref_get_name(re->ref)),
		    strlen(refname)) == 0) {
			return re->ref;
		}
	}

	return NULL;
}

static struct got_pathlist_entry *
find_their_ref(struct got_pathlist_head *their_refs, const char *refname)
{
	struct got_pathlist_entry *pe;

	TAILQ_FOREACH(pe, their_refs, entry) {
		const char *their_refname = pe->path;
		if (got_path_cmp(their_refname, refname,
		    strlen(their_refname), strlen(refname)) == 0) {
			return pe;
		}
	}

	return NULL;
}

static const struct got_error *
get_remote_refname(char **remote_refname, const char *remote_name,
    const char *refname)
{
	if (strncmp(refname, "refs/", 5) == 0)
		refname += 5;
	if (strncmp(refname, "heads/", 6) == 0)
		refname += 6;

	if (asprintf(remote_refname, "refs/remotes/%s/%s",
	    remote_name, refname) == -1)
		return got_error_from_errno("asprintf");

	return NULL;
}

static const struct got_error *
update_remote_ref(struct got_reference *my_ref, const char *remote_name,
    struct got_repository *repo)
{
	const struct got_error *err, *unlock_err;
	struct got_object_id *my_id;
	struct got_reference *ref = NULL;
	char *remote_refname = NULL;
	int ref_locked = 0;

	err = got_ref_resolve(&my_id, repo, my_ref);
	if (err)
		return err;

	err = get_remote_refname(&remote_refname, remote_name,
	    got_ref_get_name(my_ref));
	if (err)
		goto done;

	err = got_ref_open(&ref, repo, remote_refname, 1 /* lock */);
	if (err) {
		if (err->code != GOT_ERR_NOT_REF)
			goto done;
		err = got_ref_alloc(&ref, remote_refname, my_id);
		if (err)
			goto done;
	} else {
		ref_locked = 1;
		err = got_ref_change_ref(ref, my_id);
		if (err)
			goto done;
	}

	err = got_ref_write(ref, repo);
done:
	if (ref) {
		if (ref_locked) {
			unlock_err = got_ref_unlock(ref);
			if (unlock_err && err == NULL)
				err = unlock_err;
		}
		got_ref_close(ref);
	}
	free(my_id);
	free(remote_refname);
	return err;
}

const struct got_error*
got_send_pack(const char *remote_name, struct got_pathlist_head *branch_names,
    struct got_pathlist_head *tag_names,
    struct got_pathlist_head *delete_branches,
    int verbosity, int overwrite_refs, int sendfd,
    struct got_repository *repo, got_send_progress_cb progress_cb,
    void *progress_arg, got_cancel_cb cancel_cb, void *cancel_arg)
{
	int imsg_sendfds[2];
	int npackfd = -1, nsendfd = -1;
	int sendstatus, done = 0;
	const struct got_error *err;
	struct imsgbuf sendibuf;
	pid_t sendpid = -1;
	struct got_reflist_head refs;
	struct got_pathlist_head have_refs;
	struct got_pathlist_head their_refs;
	struct got_pathlist_entry *pe;
	struct got_reflist_entry *re;
	struct got_object_id **our_ids = NULL;
	struct got_object_id **their_ids = NULL;
	int i, nours = 0, ntheirs = 0;
	size_t nalloc_ours = 0, nalloc_theirs = 0;
	int refs_to_send = 0, refs_to_delete = 0;
	off_t bytes_sent = 0, bytes_sent_cur = 0;
	struct pack_progress_arg ppa;
	uint8_t packsha1[SHA1_DIGEST_LENGTH];
	int packfd = -1;
	FILE *delta_cache = NULL;

	TAILQ_INIT(&refs);
	TAILQ_INIT(&have_refs);
	TAILQ_INIT(&their_refs);

	TAILQ_FOREACH(pe, branch_names, entry) {
		const char *branchname = pe->path;
		if (strncmp(branchname, "refs/heads/", 11) != 0) {
			char *s;
			if (asprintf(&s, "refs/heads/%s", branchname) == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}
			err = insert_ref(&refs, s, repo);
			free(s);
		} else {
			err = insert_ref(&refs, branchname, repo);
		}
		if (err)
			goto done;
	}

	TAILQ_FOREACH(pe, delete_branches, entry) {
		const char *branchname = pe->path;
		struct got_reference *ref;
		if (strncmp(branchname, "refs/heads/", 11) != 0) {
			err = got_error_fmt(GOT_ERR_SEND_DELETE_REF, "%s",
			    branchname);
			goto done;
		}
		ref = find_ref(&refs, branchname);
		if (ref) {
			err = got_error_fmt(GOT_ERR_SEND_DELETE_REF,
			    "changes on %s will be sent to server",
			    branchname);
			goto done;
		}
	}

	TAILQ_FOREACH(pe, tag_names, entry) {
		const char *tagname = pe->path;
		if (strncmp(tagname, "refs/tags/", 10) != 0) {
			char *s;
			if (asprintf(&s, "refs/tags/%s", tagname) == -1) {
				err = got_error_from_errno("asprintf");
				goto done;
			}
			err = insert_ref(&refs, s, repo);
			free(s);
		} else {
			err = insert_ref(&refs, tagname, repo);
		}
		if (err)
			goto done;
	}

	if (TAILQ_EMPTY(&refs) && TAILQ_EMPTY(delete_branches)) {
		err = got_error(GOT_ERR_SEND_EMPTY);
		goto done;
	}

	TAILQ_FOREACH(re, &refs, entry) {
		struct got_object_id *id;
		int obj_type;

		if (got_ref_is_symbolic(re->ref)) {
			err = got_error_fmt(GOT_ERR_BAD_REF_TYPE,
			    "cannot send symbolic reference %s",
			    got_ref_get_name(re->ref));
			goto done;
		}

		err = got_ref_resolve(&id, repo, re->ref);
		if (err)
			goto done;
		err = got_object_get_type(&obj_type, repo, id);
		free(id);
		if (err)
			goto done;
		switch (obj_type) {
		case GOT_OBJ_TYPE_COMMIT:
		case GOT_OBJ_TYPE_TAG:
			break;
		default:
			err = got_error_fmt(GOT_ERR_OBJ_TYPE,
			    "cannot send %s", got_ref_get_name(re->ref));
			goto done;
		}
	}

	packfd = got_opentempfd();
	if (packfd == -1) {
		err = got_error_from_errno("got_opentempfd");
		goto done;
	}

	delta_cache = got_opentemp();
	if (delta_cache == NULL) {
		err = got_error_from_errno("got_opentemp");
		goto done;
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, imsg_sendfds) == -1) {
		err = got_error_from_errno("socketpair");
		goto done;
	}

	sendpid = fork();
	if (sendpid == -1) {
		err = got_error_from_errno("fork");
		goto done;
	} else if (sendpid == 0){
		got_privsep_exec_child(imsg_sendfds,
		    GOT_PATH_PROG_SEND_PACK, got_repo_get_path(repo));
	}

	if (close(imsg_sendfds[1]) == -1) {
		err = got_error_from_errno("close");
		goto done;
	}
	imsg_init(&sendibuf, imsg_sendfds[0]);
	nsendfd = dup(sendfd);
	if (nsendfd == -1) {
		err = got_error_from_errno("dup");
		goto done;
	}

	/*
	 * Convert reflist to pathlist since the privsep layer
	 * is linked into helper programs which lack reference.c.
	 */
	TAILQ_FOREACH(re, &refs, entry) {
		struct got_object_id *id;
		err = got_ref_resolve(&id, repo, re->ref);
		if (err)
			goto done;
		err = got_pathlist_append(&have_refs,
		    got_ref_get_name(re->ref), id);
		if (err)
			goto done;
		/*
		 * Also prepare the array of our object IDs which
		 * will be needed for generating a pack file.
		 */
		err = realloc_ids(&our_ids, &nalloc_ours, nours + 1);
		if (err)
			goto done;
		our_ids[nours] = id;
		nours++;
	}

	err = got_privsep_send_send_req(&sendibuf, nsendfd, &have_refs,
	    delete_branches, verbosity);
	if (err)
		goto done;
	nsendfd = -1;

	err = got_privsep_recv_send_remote_refs(&their_refs, &sendibuf);
	if (err)
		goto done;

	/*
	 * Process references reported by the server.
	 * Push appropriate object IDs onto the "their IDs" array.
	 * This array will be used to exclude objects which already
	 * exist on the server from our pack file.
	 */
	TAILQ_FOREACH(pe, &their_refs, entry) {
		const char *refname = pe->path;
		struct got_object_id *their_id = pe->data;
		int have_their_id;
		struct got_object *obj;
		struct got_reference *my_ref = NULL;
		int is_tag = 0;

		/* Don't blindly trust the server to send us valid names. */
		if (!got_ref_name_is_valid(refname))
			continue;

		if (strncmp(refname, "refs/tags/", 10) == 0)
			is_tag = 1;
		/*
		 * Find out whether this is a reference we want to upload.
		 * Otherwise we can still use this reference as a hint to
		 * avoid uploading any objects the server already has.
		 */
		my_ref = find_ref(&refs, refname);
		if (my_ref) {
			struct got_object_id *my_id;
			err = got_ref_resolve(&my_id, repo, my_ref);
			if (err)
				goto done;
			if (got_object_id_cmp(my_id, their_id) != 0) {
				if (!overwrite_refs && is_tag) {
					err = got_error_fmt(
					    GOT_ERR_SEND_TAG_EXISTS,
					    "%s", refname);
					free(my_id);
					goto done;
				}
				refs_to_send++;
			}
			free(my_id);
		}

		/* Check if their object exists locally. */
		err = got_object_open(&obj, repo, their_id);
		if (err) {
			if (err->code != GOT_ERR_NO_OBJ)
				goto done;
			if (!overwrite_refs && my_ref != NULL) {
				err = got_error_fmt(GOT_ERR_SEND_ANCESTRY,
				    "%s", refname);
				goto done;
			}
			have_their_id = 0;
		} else {
			got_object_close(obj);
			have_their_id = 1;
		}

		err = realloc_ids(&their_ids, &nalloc_theirs, ntheirs + 1);
		if (err)
			goto done;

		if (have_their_id) {
			/* Enforce linear ancestry if required. */
			if (!overwrite_refs && my_ref && !is_tag) {
				struct got_object_id *my_id;
				err = got_ref_resolve(&my_id, repo, my_ref);
				if (err)
					goto done;
				err = check_linear_ancestry(refname, my_id,
				    their_id, repo, cancel_cb, cancel_arg);
				free(my_id);
				my_id = NULL;
				if (err)
					goto done;
			}
			/* Exclude any objects reachable via their ID. */
			their_ids[ntheirs] = got_object_id_dup(their_id);
			if (their_ids[ntheirs] == NULL) {
				err = got_error_from_errno("got_object_id_dup");
				goto done;
			}
			ntheirs++;
		} else if (!is_tag) {
			char *remote_refname;
			struct got_reference *ref;
			/*
			 * Exclude any objects which exist on the server
			 * according to a locally cached remote reference.
			 */
			err = get_remote_refname(&remote_refname,
			    remote_name, refname);
			if (err)
				goto done;
			err = got_ref_open(&ref, repo, remote_refname, 0);
			free(remote_refname);
			if (err) {
				if (err->code != GOT_ERR_NOT_REF)
					goto done;
			} else {
				err = got_ref_resolve(&their_ids[ntheirs],
				    repo, ref);
				got_ref_close(ref);
				if (err)
					goto done;
				ntheirs++;
			}
		}
	}

	/* Account for any new references we are going to upload. */
	TAILQ_FOREACH(re, &refs, entry) {
		if (find_their_ref(&their_refs,
		    got_ref_get_name(re->ref)) == NULL)
			refs_to_send++;
	}

	/* Account for any existing references we are going to delete. */
	TAILQ_FOREACH(pe, delete_branches, entry) {
		const char *branchname = pe->path;
		if (find_their_ref(&their_refs, branchname))
			refs_to_delete++;
	}

	if (refs_to_send == 0 && refs_to_delete == 0) {
		got_privsep_send_stop(imsg_sendfds[0]);
		goto done;
	}

	if (refs_to_send > 0) {
		struct got_ratelimit rl;
		got_ratelimit_init(&rl, 0, 500);
		memset(&ppa, 0, sizeof(ppa));
		ppa.progress_cb = progress_cb;
		ppa.progress_arg = progress_arg;
		err = got_pack_create(packsha1, packfd, delta_cache,
		    their_ids, ntheirs, our_ids, nours, repo, 0, 1, 0,
		    pack_progress, &ppa, &rl, cancel_cb, cancel_arg);
		if (err)
			goto done;

		npackfd = dup(packfd);
		if (npackfd == -1) {
			err = got_error_from_errno("dup");
			goto done;
		}
		err = got_privsep_send_packfd(&sendibuf, npackfd);
		if (err != NULL)
			goto done;
		npackfd = -1;
	} else {
		err = got_privsep_send_packfd(&sendibuf, -1);
		if (err != NULL)
			goto done;
	}

	while (!done) {
		int success = 0;
		char *refname = NULL;
		char *errmsg = NULL;

		if (cancel_cb) {
			err = (*cancel_cb)(cancel_arg);
			if (err)
				goto done;
		}
		err = got_privsep_recv_send_progress(&done, &bytes_sent,
		    &success, &refname, &errmsg, &sendibuf);
		if (err)
			goto done;
		if (refname && got_ref_name_is_valid(refname) && success &&
		    strncmp(refname, "refs/tags/", 10) != 0) {
			struct got_reference *my_ref;
			/*
			 * The server has accepted our changes.
			 * Update our reference in refs/remotes/ accordingly.
			 */
			my_ref = find_ref(&refs, refname);
			if (my_ref) {
				err = update_remote_ref(my_ref, remote_name,
				    repo);
				if (err)
					goto done;
			}
		}
		if (refname != NULL ||
		    bytes_sent_cur != bytes_sent) {
			err = progress_cb(progress_arg, ppa.ncolored,
			    ppa.nfound, ppa.ntrees, ppa.packfile_size,
			    ppa.ncommits, ppa.nobj_total, ppa.nobj_deltify,
			    ppa.nobj_written, bytes_sent,
			    refname, errmsg, success);
			if (err) {
				free(refname);
				free(errmsg);
				goto done;
			}
			bytes_sent_cur = bytes_sent;
		}
		free(refname);
		free(errmsg);
	}
done:
	if (sendpid != -1) {
		if (err)
			got_privsep_send_stop(imsg_sendfds[0]);
		if (waitpid(sendpid, &sendstatus, 0) == -1 && err == NULL)
			err = got_error_from_errno("waitpid");
	}
	if (packfd != -1 && close(packfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (delta_cache && fclose(delta_cache) == EOF && err == NULL)
		err = got_error_from_errno("fclose");
	if (nsendfd != -1 && close(nsendfd) == -1 && err == NULL)
		err = got_error_from_errno("close");
	if (npackfd != -1 && close(npackfd) == -1 && err == NULL)
		err = got_error_from_errno("close");

	got_ref_list_free(&refs);
	got_pathlist_free(&have_refs, GOT_PATHLIST_FREE_NONE);
	got_pathlist_free(&their_refs, GOT_PATHLIST_FREE_NONE);
	for (i = 0; i < nours; i++)
		free(our_ids[i]);
	free(our_ids);
	for (i = 0; i < ntheirs; i++)
		free(their_ids[i]);
	free(their_ids);
	return err;
}
