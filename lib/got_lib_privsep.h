/*
 * Copyright (c) 2018, 2019 Stefan Sperling <stsp@openbsd.org>
 * Copyright (c) 2019, Ori Bernstein <ori@openbsd.org>
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

/*
 * All code runs under the same UID but sensitive code paths are
 * run in a separate process with tighter pledge(2) promises.
 * Data is communicated between processes via imsg_flush(3) and imsg_read(3).
 * This behaviour is transparent to users of the library.
 *
 * We generally transmit data in imsg buffers, split across several messages
 * if necessary. File descriptors are used in cases where this is impractical,
 * such as when accessing pack files or when transferring large blobs.
 *
 * We exec(2) after a fork(2). Parts of our library functionality are
 * accessible via separate executables in a libexec directory.
 */

#define GOT_IMSG_FD_CHILD (STDERR_FILENO + 1)

#ifndef GOT_LIBEXECDIR
#define GOT_LIBEXECDIR /usr/libexec
#endif

/* Names of helper programs in libexec directory */
#define GOT_PROG_READ_OBJECT	got-read-object
#define GOT_PROG_READ_TREE	got-read-tree
#define GOT_PROG_READ_COMMIT	got-read-commit
#define GOT_PROG_READ_BLOB	got-read-blob
#define GOT_PROG_READ_TAG	got-read-tag
#define GOT_PROG_READ_PACK	got-read-pack
#define GOT_PROG_READ_GITCONFIG	got-read-gitconfig
#define GOT_PROG_READ_GOTCONFIG	got-read-gotconfig
#define GOT_PROG_FETCH_PACK	got-fetch-pack
#define GOT_PROG_INDEX_PACK	got-index-pack
#define GOT_PROG_SEND_PACK	got-send-pack

#define GOT_STRINGIFY(x) #x
#define GOT_STRINGVAL(x) GOT_STRINGIFY(x)

/* Paths to helper programs in libexec directory */
#define GOT_PATH_PROG_READ_OBJECT \
	GOT_STRINGVAL(GOT_LIBEXECDIR) "/" GOT_STRINGVAL(GOT_PROG_READ_OBJECT)
#define GOT_PATH_PROG_READ_TREE \
	GOT_STRINGVAL(GOT_LIBEXECDIR) "/" GOT_STRINGVAL(GOT_PROG_READ_TREE)
#define GOT_PATH_PROG_READ_COMMIT \
	GOT_STRINGVAL(GOT_LIBEXECDIR) "/" GOT_STRINGVAL(GOT_PROG_READ_COMMIT)
#define GOT_PATH_PROG_READ_BLOB \
	GOT_STRINGVAL(GOT_LIBEXECDIR) "/" GOT_STRINGVAL(GOT_PROG_READ_BLOB)
#define GOT_PATH_PROG_READ_TAG \
	GOT_STRINGVAL(GOT_LIBEXECDIR) "/" GOT_STRINGVAL(GOT_PROG_READ_TAG)
#define GOT_PATH_PROG_READ_PACK \
	GOT_STRINGVAL(GOT_LIBEXECDIR) "/" GOT_STRINGVAL(GOT_PROG_READ_PACK)
#define GOT_PATH_PROG_READ_GITCONFIG \
	GOT_STRINGVAL(GOT_LIBEXECDIR) "/" GOT_STRINGVAL(GOT_PROG_READ_GITCONFIG)
#define GOT_PATH_PROG_READ_GOTCONFIG \
	GOT_STRINGVAL(GOT_LIBEXECDIR) "/" GOT_STRINGVAL(GOT_PROG_READ_GOTCONFIG)
#define GOT_PATH_PROG_FETCH_PACK \
	GOT_STRINGVAL(GOT_LIBEXECDIR) "/" GOT_STRINGVAL(GOT_PROG_FETCH_PACK)
#define GOT_PATH_PROG_SEND_PACK \
	GOT_STRINGVAL(GOT_LIBEXECDIR) "/" GOT_STRINGVAL(GOT_PROG_SEND_PACK)
#define GOT_PATH_PROG_INDEX_PACK \
	GOT_STRINGVAL(GOT_LIBEXECDIR) "/" GOT_STRINGVAL(GOT_PROG_INDEX_PACK)

struct got_privsep_child {
	int imsg_fd;
	pid_t pid;
	struct imsgbuf *ibuf;
};

enum got_imsg_type {
	/* An error occured while processing a request. */
	GOT_IMSG_ERROR,

	/* Stop the child process. */
	GOT_IMSG_STOP,

	/*
	 * Messages concerned with read access to objects in a repository.
	 * Object and pack files are opened by the main process, where
	 * data may be read as a byte string but without any interpretation.
	 * Decompression and parsing of object and pack files occurs in a
	 * separate process which runs under pledge("stdio recvfd").
	 * This sandboxes our own repository parsing code, as well as zlib.
	 */
	GOT_IMSG_OBJECT_REQUEST,
	GOT_IMSG_OBJECT,
	GOT_IMSG_COMMIT_REQUEST,
	GOT_IMSG_COMMIT,
	GOT_IMSG_COMMIT_LOGMSG,
	GOT_IMSG_TREE_REQUEST,
	GOT_IMSG_TREE,
	GOT_IMSG_TREE_ENTRY,
	GOT_IMSG_BLOB_REQUEST,
	GOT_IMSG_BLOB_OUTFD,
	GOT_IMSG_BLOB,
	GOT_IMSG_TAG_REQUEST,
	GOT_IMSG_TAG,
	GOT_IMSG_TAG_TAGMSG,

	/* Messages related to networking. */
	GOT_IMSG_FETCH_REQUEST,
	GOT_IMSG_FETCH_HAVE_REF,
	GOT_IMSG_FETCH_WANTED_BRANCH,
	GOT_IMSG_FETCH_WANTED_REF,
	GOT_IMSG_FETCH_OUTFD,
	GOT_IMSG_FETCH_SYMREFS,
	GOT_IMSG_FETCH_REF,
	GOT_IMSG_FETCH_SERVER_PROGRESS,
	GOT_IMSG_FETCH_DOWNLOAD_PROGRESS,
	GOT_IMSG_FETCH_DONE,
	GOT_IMSG_IDXPACK_REQUEST,
	GOT_IMSG_IDXPACK_OUTFD,
	GOT_IMSG_IDXPACK_PROGRESS,
	GOT_IMSG_IDXPACK_DONE,

	/* Messages related to pack files. */
	GOT_IMSG_PACKIDX,
	GOT_IMSG_PACK,
	GOT_IMSG_PACKED_OBJECT_REQUEST,
	GOT_IMSG_COMMIT_TRAVERSAL_REQUEST,
	GOT_IMSG_TRAVERSED_COMMITS,
	GOT_IMSG_COMMIT_TRAVERSAL_DONE,

	/* Message sending file descriptor to a temporary file. */
	GOT_IMSG_TMPFD,

	/* Messages related to gitconfig files. */
	GOT_IMSG_GITCONFIG_PARSE_REQUEST,
	GOT_IMSG_GITCONFIG_REPOSITORY_FORMAT_VERSION_REQUEST,
	GOT_IMSG_GITCONFIG_REPOSITORY_EXTENSIONS_REQUEST,
	GOT_IMSG_GITCONFIG_AUTHOR_NAME_REQUEST,
	GOT_IMSG_GITCONFIG_AUTHOR_EMAIL_REQUEST,
	GOT_IMSG_GITCONFIG_REMOTES_REQUEST,
	GOT_IMSG_GITCONFIG_INT_VAL,
	GOT_IMSG_GITCONFIG_STR_VAL,
	GOT_IMSG_GITCONFIG_REMOTES,
	GOT_IMSG_GITCONFIG_REMOTE,
	GOT_IMSG_GITCONFIG_OWNER_REQUEST,
	GOT_IMSG_GITCONFIG_OWNER,

	/* Messages related to gotconfig files. */
	GOT_IMSG_GOTCONFIG_PARSE_REQUEST,
	GOT_IMSG_GOTCONFIG_AUTHOR_REQUEST,
	GOT_IMSG_GOTCONFIG_REMOTES_REQUEST,
	GOT_IMSG_GOTCONFIG_INT_VAL,
	GOT_IMSG_GOTCONFIG_STR_VAL,
	GOT_IMSG_GOTCONFIG_REMOTES,
	GOT_IMSG_GOTCONFIG_REMOTE,
};

/* Structure for GOT_IMSG_ERROR. */
struct got_imsg_error {
	int code; /* an error code from got_error.h */
	int errno_code; /* in case code equals GOT_ERR_ERRNO */
} __attribute__((__packed__));

/*
 * Structure for GOT_IMSG_TREE_REQUEST and GOT_IMSG_OBJECT data.
 */
struct got_imsg_object {
	uint8_t id[SHA1_DIGEST_LENGTH];

	/* These fields are the same as in struct got_object. */
	int type;
	int flags;
	size_t hdrlen;
	size_t size;
	off_t pack_offset;
	int pack_idx;
}  __attribute__((__packed__));

/* Structure for GOT_IMSG_COMMIT data. */
struct got_imsg_commit_object {
	uint8_t tree_id[SHA1_DIGEST_LENGTH];
	size_t author_len;
	time_t author_time;
	time_t author_gmtoff;
	size_t committer_len;
	time_t committer_time;
	time_t committer_gmtoff;
	size_t logmsg_len;
	int nparents;

	/*
	 * Followed by author_len + committer_len data bytes
	 */

	/* Followed by 'nparents' SHA1_DIGEST_LENGTH length strings */

	/*
	 * Followed by 'logmsg_len' bytes of commit log message data in
	 * one or more GOT_IMSG_COMMIT_LOGMSG messages.
	 */
} __attribute__((__packed__));


/* Structure for GOT_IMSG_TREE_ENTRY. */
struct got_imsg_tree_entry {
	char id[SHA1_DIGEST_LENGTH];
	mode_t mode;
	/* Followed by entry's name in remaining data of imsg buffer. */
} __attribute__((__packed__));

/* Structure for GOT_IMSG_TREE_OBJECT_REPLY data. */
struct got_imsg_tree_object {
	int nentries; /* This many TREE_ENTRY messages follow. */
};

/* Structure for GOT_IMSG_BLOB. */
struct got_imsg_blob {
	size_t size;
	size_t hdrlen;

	/*
	 * If size <= GOT_PRIVSEP_INLINE_BLOB_DATA_MAX, blob data follows
	 * in the imsg buffer. Otherwise, blob data has been written to a
	 * file descriptor passed via the GOT_IMSG_BLOB_OUTFD imsg.
	 */
#define GOT_PRIVSEP_INLINE_BLOB_DATA_MAX \
	(MAX_IMSGSIZE - IMSG_HEADER_SIZE - sizeof(struct got_imsg_blob))
};


/* Structure for GOT_IMSG_TAG data. */
struct got_imsg_tag_object {
	uint8_t id[SHA1_DIGEST_LENGTH];
	int obj_type;
	size_t tag_len;
	size_t tagger_len;
	time_t tagger_time;
	time_t tagger_gmtoff;
	size_t tagmsg_len;

	/*
	 * Followed by tag_len + tagger_len data bytes
	 */

	/*
	 * Followed by 'tagmsg_len' bytes of tag message data in
	 * one or more GOT_IMSG_TAG_TAGMSG messages.
	 */
} __attribute__((__packed__));

/* Structure for GOT_IMSG_FETCH_HAVE_REF data. */
struct got_imsg_fetch_have_ref {
	uint8_t id[SHA1_DIGEST_LENGTH];
	size_t name_len;
	/* Followed by name_len data bytes. */
} __attribute__((__packed__));

/* Structure for GOT_IMSG_FETCH_WANTED_BRANCH data. */
struct got_imsg_fetch_wanted_branch {
	size_t name_len;
	/* Followed by name_len data bytes. */
} __attribute__((__packed__));

/* Structure for GOT_IMSG_FETCH_WANTED_REF data. */
struct got_imsg_fetch_wanted_ref {
	size_t name_len;
	/* Followed by name_len data bytes. */
} __attribute__((__packed__));

/* Structure for GOT_IMSG_FETCH_REQUEST data. */
struct got_imsg_fetch_request {
	int fetch_all_branches;
	int list_refs_only;
	int verbosity;
	size_t n_have_refs;
	size_t n_wanted_branches;
	size_t n_wanted_refs;
	/* Followed by n_have_refs GOT_IMSG_FETCH_HAVE_REF messages. */
	/* Followed by n_wanted_branches times GOT_IMSG_FETCH_WANTED_BRANCH. */
	/* Followed by n_wanted_refs times GOT_IMSG_FETCH_WANTED_REF. */
} __attribute__((__packed__));

/* Structures for GOT_IMSG_FETCH_SYMREFS data. */
struct got_imsg_fetch_symref {
	size_t name_len;
	size_t target_len;

	/*
	 * Followed by name_len + target_len data bytes.
	 */
} __attribute__((__packed__));

struct got_imsg_fetch_symrefs {
	size_t nsymrefs;

	/* Followed by nsymrefs times of got_imsg_fetch_symref data. */
} __attribute__((__packed__));

/* Structure for GOT_IMSG_FETCH_REF data. */
struct got_imsg_fetch_ref {
	/* Describes a reference which will be fetched. */
	uint8_t refid[SHA1_DIGEST_LENGTH];
	/* Followed by reference name in remaining data of imsg buffer. */
};

/* Structure for GOT_IMSG_FETCH_DOWNLOAD_PROGRESS data. */
struct got_imsg_fetch_download_progress {
	/* Number of packfile data bytes downloaded so far. */
	off_t packfile_bytes;
};

/* Structure for GOT_IMSG_IDXPACK_REQUEST data. */
struct got_imsg_index_pack_request {
	uint8_t pack_hash[SHA1_DIGEST_LENGTH];
} __attribute__((__packed__));

/* Structure for GOT_IMSG_IDXPACK_PROGRESS data. */
struct got_imsg_index_pack_progress {
	/* Total number of objects in pack file. */
	int nobj_total;

	/* Number of objects indexed so far. */
	int nobj_indexed;

	/* Number of non-deltified objects in pack file. */
	int nobj_loose;

	/* Number of deltified objects resolved so far. */
	int nobj_resolved;
};

/* Structure for GOT_IMSG_PACKIDX. */
struct got_imsg_packidx {
	size_t len;
	/* Additionally, a file desciptor is passed via imsg. */
};

/* Structure for GOT_IMSG_PACK. */
struct got_imsg_pack {
	char path_packfile[PATH_MAX];
	size_t filesize;
	/* Additionally, a file desciptor is passed via imsg. */
} __attribute__((__packed__));

/*
 * Structure for GOT_IMSG_PACKED_OBJECT_REQUEST data.
 */
struct got_imsg_packed_object {
	uint8_t id[SHA1_DIGEST_LENGTH];
	int idx;
} __attribute__((__packed__));

/* Structure for GOT_IMSG_COMMIT_TRAVERSAL_REQUEST  */
struct got_imsg_commit_traversal_request {
	uint8_t id[SHA1_DIGEST_LENGTH];
	int idx;
	size_t path_len;
	/* Followed by path_len bytes of path data */
} __attribute__((__packed__));

/* Structure for GOT_IMSG_TRAVERSED_COMMITS  */
struct got_imsg_traversed_commits {
	size_t ncommits;
	/* Followed by ncommit IDs of SHA1_DIGEST_LENGTH each */
} __attribute__((__packed__));

/*
 * Structure for GOT_IMSG_GITCONFIG_REMOTE data.
 */
struct got_imsg_remote {
	size_t name_len;
	size_t url_len;
	int mirror_references;
	int nbranches;

	/* Followed by name_len + url_len data bytes. */
	/* Followed by nbranches GOT_IMSG_GITCONFIG_STR_VAL messages. */
} __attribute__((__packed__));

/*
 * Structure for GOT_IMSG_GITCONFIG_REMOTES data.
 */
struct got_imsg_remotes {
	int nremotes; /* This many GOT_IMSG_GITCONFIG_REMOTE messages follow. */
};

struct got_remote_repo;
struct got_pack;
struct got_packidx;
struct got_pathlist_head;

const struct got_error *got_send_ack(pid_t);
const struct got_error *got_privsep_wait_for_child(pid_t);
const struct got_error *got_privsep_flush_imsg(struct imsgbuf *);
const struct got_error *got_privsep_send_stop(int);
const struct got_error *got_privsep_recv_imsg(struct imsg *, struct imsgbuf *,
    size_t);
void got_privsep_send_error(struct imsgbuf *, const struct got_error *);
const struct got_error *got_privsep_send_ack(struct imsgbuf *);
const struct got_error *got_privsep_wait_ack(struct imsgbuf *);
const struct got_error *got_privsep_send_obj_req(struct imsgbuf *, int);
const struct got_error *got_privsep_send_commit_req(struct imsgbuf *, int,
    struct got_object_id *, int);
const struct got_error *got_privsep_send_tree_req(struct imsgbuf *, int,
    struct got_object_id *, int);
const struct got_error *got_privsep_send_tag_req(struct imsgbuf *, int,
    struct got_object_id *, int);
const struct got_error *got_privsep_send_blob_req(struct imsgbuf *, int,
    struct got_object_id *, int);
const struct got_error *got_privsep_send_blob_outfd(struct imsgbuf *, int);
const struct got_error *got_privsep_send_tmpfd(struct imsgbuf *, int);
const struct got_error *got_privsep_send_obj(struct imsgbuf *,
    struct got_object *);
const struct got_error *got_privsep_send_index_pack_req(struct imsgbuf *,
    uint8_t *, int);
const struct got_error *got_privsep_send_index_pack_outfd(struct imsgbuf *,
    int);
const struct got_error *got_privsep_recv_index_progress(int *, int *, int *,
    int *, int *, struct imsgbuf *ibuf);
const struct got_error *got_privsep_send_fetch_req(struct imsgbuf *, int,
    struct got_pathlist_head *, int, struct got_pathlist_head *,
    struct got_pathlist_head *, int, int);
const struct got_error *got_privsep_send_fetch_outfd(struct imsgbuf *, int);
const struct got_error *got_privsep_recv_fetch_progress(int *,
    struct got_object_id **, char **, struct got_pathlist_head *, char **,
    off_t *, uint8_t *, struct imsgbuf *);
const struct got_error *got_privsep_get_imsg_obj(struct got_object **,
    struct imsg *, struct imsgbuf *);
const struct got_error *got_privsep_recv_obj(struct got_object **,
    struct imsgbuf *);
const struct got_error *got_privsep_send_commit(struct imsgbuf *,
    struct got_commit_object *);
const struct got_error *got_privsep_recv_commit(struct got_commit_object **,
    struct imsgbuf *);
const struct got_error *got_privsep_recv_tree(struct got_tree_object **,
    struct imsgbuf *);
const struct got_error *got_privsep_send_tree(struct imsgbuf *,
    struct got_pathlist_head *, int);
const struct got_error *got_privsep_send_blob(struct imsgbuf *, size_t, size_t,
    const uint8_t *);
const struct got_error *got_privsep_recv_blob(uint8_t **, size_t *, size_t *,
    struct imsgbuf *);
const struct got_error *got_privsep_send_tag(struct imsgbuf *,
    struct got_tag_object *);
const struct got_error *got_privsep_recv_tag(struct got_tag_object **,
    struct imsgbuf *);
const struct got_error *got_privsep_init_pack_child(struct imsgbuf *,
    struct got_pack *, struct got_packidx *);
const struct got_error *got_privsep_send_packed_obj_req(struct imsgbuf *, int,
    struct got_object_id *);
const struct got_error *got_privsep_send_pack_child_ready(struct imsgbuf *);

const struct got_error *got_privsep_send_gitconfig_parse_req(struct imsgbuf *,
    int);
const struct got_error *
    got_privsep_send_gitconfig_repository_format_version_req(struct imsgbuf *);
const struct got_error *got_privsep_send_gitconfig_repository_extensions_req(
    struct imsgbuf *);
const struct got_error *got_privsep_send_gitconfig_author_name_req(
    struct imsgbuf *);
const struct got_error *got_privsep_send_gitconfig_author_email_req(
    struct imsgbuf *);
const struct got_error *got_privsep_send_gitconfig_remotes_req(
    struct imsgbuf *);
const struct got_error *got_privsep_send_gitconfig_owner_req(struct imsgbuf *);
const struct got_error *got_privsep_recv_gitconfig_str(char **,
    struct imsgbuf *);
const struct got_error *got_privsep_recv_gitconfig_int(int *, struct imsgbuf *);
const struct got_error *got_privsep_recv_gitconfig_remotes(
    struct got_remote_repo **, int *, struct imsgbuf *);

const struct got_error *got_privsep_send_gotconfig_parse_req(struct imsgbuf *,
    int);
const struct got_error *got_privsep_send_gotconfig_author_req(struct imsgbuf *);
const struct got_error *got_privsep_send_gotconfig_remotes_req(
    struct imsgbuf *);
const struct got_error *got_privsep_recv_gotconfig_str(char **,
    struct imsgbuf *);
const struct got_error *got_privsep_recv_gotconfig_remotes(
    struct got_remote_repo **, int *, struct imsgbuf *);

const struct got_error *got_privsep_send_commit_traversal_request(
    struct imsgbuf *, struct got_object_id *, int, const char *);
const struct got_error *got_privsep_recv_traversed_commits(
    struct got_commit_object **, struct got_object_id **,
    struct got_object_id_queue *, struct imsgbuf *);

void got_privsep_exec_child(int[2], const char *, const char *);
