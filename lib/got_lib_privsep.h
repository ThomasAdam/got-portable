/*
 * Copyright (c) 2018 Stefan Sperling <stsp@openbsd.org>
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
 * We currently do not exec(2) after a fork(2).
 * To achieve fork+exec, relevant parts of our library functionality could
 * be made accessible via separate executables in a libexec directory.
 */

enum got_imsg_type {
	/* An error occured while processing a request. */
	GOT_IMSG_ERROR,

	/* Messages for transmitting deltas and associated delta streams. */
	GOT_IMSG_DELTA,
	GOT_IMSG_DELTA_STREAM,

	/*
	 * Messages concerned with read access to objects in a repository.
	 * Object and pack files are opened by the main process, where
	 * data may be read as a byte string but without any interpretation.
	 * Decompression and parsing of object and pack files occurs in a
	 * separate process which runs under pledge("stdio").
	 * This sandboxes our own repository parsing code, as well as zlib.
	 */
	GOT_IMSG_OBJECT,
	GOT_IMSG_COMMIT,
	GOT_IMSG_TREE,
	GOT_IMSG_TREE_ENTRY,
	GOT_IMSG_BLOB,
};

/* Structure for GOT_IMSG_ERROR. */
struct got_imsg_error {
	int code; /* an error code from got_error.h */
	int errno_code; /* in case code equals GOT_ERR_ERRNO */
};

/* Structure for GOT_IMSG_DELTA data. */
struct got_imsg_delta {
	/* These fields are the same as in struct got_delta. */
	off_t offset;
	size_t tslen;
	int type;
	size_t size;
	off_t data_offset;
	size_t delta_len;

	/*
	 * Followed by delta stream in remaining bytes of imsg buffer.
	 * If delta_len exceeds imsg buffer length, followed by one or
	 * more DELTA_STREAM messages until delta_len bytes of delta
	 * stream have been transmitted.
	 */
};

/* Structure for GOT_IMSG_DELTA_STREAM data. */
struct got_imsg_delta_stream {
	/*
	 * Empty since the following is implied:
	 * Read additional delta stream data from imsg buffer.
	 */
};

/* Structure for GOT_IMSG_OBJECT data. */
struct got_imsg_object {
	/* These fields are the same as in struct got_object. */
	int type;
	int flags;
	size_t hdrlen;
	size_t size;

	int ndeltas; /* this many GOT_IMSG_DELTA messages follow */
};

/* Structure for GOT_IMSG_COMMIT data. */
struct got_imsg_commit_object {
	uint8_t tree_id[SHA1_DIGEST_LENGTH];
	size_t author_len;
	time_t author_time;
	size_t author_tzoff_len;
	size_t committer_len;
	time_t committer_time;
	size_t committer_tzoff_len;
	size_t logmsg_len;
	int nparents;

	/*
	 * Followed by author_len + author_tzoff_len + committer_len +
	 * committer_tzoff_len + logmsg_len data bytes
	 */

	/* Followed by 'nparents' SHA1_DIGEST_LENGTH length strings */

	/* XXX should use more messages to support very large log messages */
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
};

void got_privsep_send_error(struct imsgbuf *, const struct got_error *);
const struct got_error *got_privsep_send_obj(struct imsgbuf *,
    struct got_object *, int);
const struct got_error *got_privsep_recv_obj(struct got_object **,
    struct imsgbuf *);
const struct got_error *got_privsep_send_commit(struct imsgbuf *,
    struct got_commit_object *);
const struct got_error *got_privsep_recv_commit(struct got_commit_object **,
    struct imsgbuf *);
const struct got_error *got_privsep_recv_tree(struct got_tree_object **,
    struct imsgbuf *);
const struct got_error *got_privsep_send_tree(struct imsgbuf *,
    struct got_tree_object *);
const struct got_error *got_privsep_send_blob(struct imsgbuf *, size_t);
const struct got_error *got_privsep_recv_blob(size_t *, struct imsgbuf *);

/* TODO: Implement the above, and then add more message data types here. */
