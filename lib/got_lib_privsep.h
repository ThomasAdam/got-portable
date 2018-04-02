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
 * if necessary. File descriptor passing is used in cases where this is
 * impractical, such as when accessing pack files or when transferring
 * large blobs.
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
	GOT_IMSG_LOOSE_OBJECT_HEADER_REQUEST,
	GOT_IMSG_LOOSE_OBJECT_HEADER_REPLY,
	GOT_IMSG_LOOSE_BLOB_OBJECT_REQUEST,
	GOT_IMSG_LOOSE_BLOB_OBJECT_REQUEST_OUTPUT,
	GOT_IMSG_LOOSE_BLOB_OBJECT_REPLY,
	GOT_IMSG_LOOSE_TREE_OBJECT_REQUEST,
	GOT_IMSG_LOOSE_TREE_OBJECT_REPLY,
	GOT_IMSG_TREE_ENTRY,
	GOT_IMSG_LOOSE_COMMIT_OBJECT_REQUEST,
	GOT_IMSG_LOOSE_COMMIT_OBJECT_REPLY,
	GOT_IMSG_PACKED_BLOB_OBJECT_REQUEST,
	GOT_IMSG_PACKED_BLOB_OBJECT_REQUEST_OUTPUT,
	GOT_IMSG_PACKED_BLOB_OBJECT_REPLY,
	GOT_IMSG_PACKED_TREE_OBJECT_REQUEST,
	GOT_IMSG_PACKED_TREE_OBJECT_REPLY,
	GOT_IMSG_PACKED_COMMIT_OBJECT_REQUEST,
	GOT_IMSG_PACKED_COMMIT_OBJECT_REPLY
};

/* Structure for GOT_IMSG_ERROR. */
struct got_imsg_error {
	int code; /* an error code from got_error.h */
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

/* Structure for GOT_IMSG_LOOSE_OBJECT_HEADER_REQUEST data. */
struct got_imsg_loose_object_header_request {
	/*
	 * Empty since the following is implied: If imsg fd == -1 then
	 * read raw object data from imsg buffer, else read from fd.
	 */
};

/* Structure for transmitting struct got_object data in an imsg. */
struct got_imsg_object {
	/* These fields are the same as in struct got_object. */
	int type;
	int flags;
	size_t hdrlen;
	size_t size;
	struct got_object_id id;

	int ndeltas; /* this many GOT_IMSG_DELTA messages follow */
} __attribute__((__packed__));

/* Structure for GOT_IMSG_LOOSE_OBJECT_HEADER_REPLY data. */
struct got_imsg_loose_object_header_reply {
	struct got_imsg_object iobj;
};

/* Structure for GOT_IMSG_LOOSE_BLOB_OBJECT_REQUEST data. */
struct got_imsg_loose_blob_object_request {
	struct got_imsg_object iobj;

	/*
	 * The following is implied: If imsg fd == -1 then read raw
	 * blob data from imsg buffer, else read from fd.
	 */
};

/* Structure for GOT_IMSG_LOOSE_BLOB_OBJECT_REQUEST_OUTPUT data. */
struct got_imsg_loose_blob_object_request_output {
	/*
	 * Empty since the following is implied: If imsg fd == -1 then
	 * respond with blob data in imsg buffer, else write to fd.
	 */
};

/* Structure for GOT_IMSG_LOOSE_TREE_OBJECT_REQUEST data. */
struct got_imsg_loose_tree_object_request {
	struct got_imsg_object iobj;

	/*
	 * The following is implied: If imsg fd == -1 then read raw tree
	 * data from imsg buffer, else read from fd.
	 */
};

/* Structure for GOT_IMSG_TREE_ENTRY. */
struct got_imsg_tree_entry {
	struct got_object_id id;
	mode_t mode;
	/* Followed by entry's name in remaining data of imsg buffer. */
} __attribute__((__packed__));

/* Structure for transmitting struct got_tree_object data in an imsg. */
struct got_imsg_tree_object {
	int nentries; /* This many TREE_ENTRY messages follow. */
};

/* TODO: Implement the above, and then add more message data types here. */
