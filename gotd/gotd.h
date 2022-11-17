/*
 * Copyright (c) 2022 Stefan Sperling <stsp@openbsd.org>
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


#define GOTD_UNIX_SOCKET "/var/run/gotd.sock"
#define GOTD_UNIX_SOCKET_BACKLOG 10
#define GOTD_UNIX_GROUP	"_gotsh"
#define GOTD_USER	"_gotd"
#define GOTD_CONF_PATH	"/etc/gotd.conf"

#define GOTD_MAXCLIENTS		1024
#define GOTD_FD_RESERVE		5
#define GOTD_FD_NEEDED		6
#define GOTD_FILENO_MSG_PIPE	3

/* Client hash tables need some extra room. */
#define GOTD_CLIENT_TABLE_SIZE (GOTD_MAXCLIENTS * 4)

enum gotd_procid {
	PROC_GOTD	= 0,
	PROC_REPO_READ,
	PROC_REPO_WRITE,
	PROC_MAX,
};

struct gotd_imsgev {
	struct imsgbuf	 ibuf;
	void		(*handler)(int, short, void *);
	void		*handler_arg;
	struct event	 ev;
	short		 events;
};

struct gotd_child_proc {
	pid_t pid;
	enum gotd_procid type;
	char repo_name[NAME_MAX];
	char chroot_path[PATH_MAX];
	int pipe[2];
	struct gotd_imsgev iev;
	size_t nhelpers;
};

enum gotd_access {
	GOTD_ACCESS_PERMITTED = 1,
	GOTD_ACCESS_DENIED
};

struct gotd_access_rule {
	STAILQ_ENTRY(gotd_access_rule) entry;

	enum gotd_access access;

	int authorization;
#define GOTD_AUTH_READ		0x1
#define GOTD_AUTH_WRITE		0x2

	char *identifier;
};
STAILQ_HEAD(gotd_access_rule_list, gotd_access_rule);

struct gotd_repo {
	TAILQ_ENTRY(gotd_repo)	 entry;

	char name[NAME_MAX];
	char path[PATH_MAX];

	struct gotd_access_rule_list rules;
};
TAILQ_HEAD(gotd_repolist, gotd_repo);

enum gotd_client_state {
	GOTD_STATE_EXPECT_LIST_REFS,
	GOTD_STATE_EXPECT_CAPABILITIES,
	GOTD_STATE_EXPECT_WANT,
	GOTD_STATE_EXPECT_REF_UPDATE,
	GOTD_STATE_EXPECT_MORE_REF_UPDATES,
	GOTD_STATE_EXPECT_HAVE,
	GOTD_STATE_EXPECT_PACKFILE,
	GOTD_STATE_EXPECT_DONE,
	GOTD_STATE_DONE,
};

struct gotd_client_capability {
	char *key;
	char *value;
};

struct gotd_object_id_array {
	struct got_object_id		**ids;
	size_t				 nalloc;
	size_t				 nids;
};

struct gotd {
	pid_t pid;
	char unix_socket_path[PATH_MAX];
	char unix_group_name[32];
	char user_name[32];
	struct gotd_repolist repos;
	int nrepos;
	int verbosity;
	struct event ev;
	struct event pause;
	struct gotd_child_proc *procs;
	int nprocs;
};

enum gotd_imsg_type {
	/* An error occured while processing a request. */
	GOTD_IMSG_ERROR,

	/* Commands used by gotctl(8). */
	GOTD_IMSG_INFO,
	GOTD_IMSG_INFO_REPO,
	GOTD_IMSG_INFO_CLIENT,
	GOTD_IMSG_STOP,

	/* Request a list of references. */
	GOTD_IMSG_LIST_REFS,
	GOTD_IMSG_LIST_REFS_INTERNAL,

	/* References. */
	GOTD_IMSG_REFLIST,
	GOTD_IMSG_REF,
	GOTD_IMSG_SYMREF,

	/* Git protocol capabilities. */
	GOTD_IMSG_CAPABILITIES,
	GOTD_IMSG_CAPABILITY,

	/* Git protocol chatter. */
	GOTD_IMSG_WANT,		/* The client wants an object. */
	GOTD_IMSG_HAVE,		/* The client has an object. */
	GOTD_IMSG_ACK,		/* The server has an object or a reference. */
	GOTD_IMSG_NAK,		/* The server does not have an object/ref. */
	GOTD_IMSG_REF_UPDATE,	/* The client wants to update a reference. */
	GOTD_IMSG_REF_DELETE,	/* The client wants to delete a reference. */
	GOTD_IMSG_FLUSH,	/* The client sent a flush packet. */
	GOTD_IMSG_DONE,		/* The client is done chatting. */

	/* Sending or receiving a pack file. */
	GOTD_IMSG_SEND_PACKFILE, /* The server is sending a pack file. */
	GOTD_IMSG_RECV_PACKFILE, /* The server is receiving a pack file. */
	GOTD_IMSG_PACKIDX_FILE,  /* Temporary file handle for new pack index. */
	GOTD_IMSG_PACKFILE_PIPE, /* Pipe to send/receive a pack file stream. */
	GOTD_IMSG_PACKFILE_PROGRESS, /* Progress reporting. */
	GOTD_IMSG_PACKFILE_READY, /* Pack file is ready to be sent. */
	GOTD_IMSG_PACKFILE_STATUS, /* Received pack success/failure status. */
	GOTD_IMSG_PACKFILE_INSTALL, /* Received pack file can be installed. */
	GOTD_IMSG_PACKFILE_DONE, /* Pack file has been sent/received. */

	/* Reference updates. */
	GOTD_IMSG_REF_UPDATES_START, /* Ref updates starting. */
	GOTD_IMSG_REF_UPDATE_OK, /* Update went OK. */
	GOTD_IMSG_REF_UPDATE_NG, /* Update was not good. */
	GOTD_IMSG_REFS_UPDATED, /* The server proccessed all ref updates. */

	/* Client is disconnecting. */
	GOTD_IMSG_DISCONNECT,
};

/* Structure for GOTD_IMSG_ERROR. */
struct gotd_imsg_error {
	int code; /* an error code from got_error.h */
	int errno_code; /* in case code equals GOT_ERR_ERRNO */
	uint32_t client_id;
	char msg[GOT_ERR_MAX_MSG_SIZE];
} __attribute__((__packed__));

/* Structure for GOTD_IMSG_INFO. */
struct gotd_imsg_info {
	pid_t pid;
	int verbosity;
	int nrepos;
	int nclients;

	/* Followed by nrepos GOTD_IMSG_INFO_REPO messages. */
	/* Followed by nclients GOTD_IMSG_INFO_CLIENT messages. */
};

/* Structure for GOTD_IMSG_INFO_REPO. */
struct gotd_imsg_info_repo {
	char repo_name[NAME_MAX];
	char repo_path[PATH_MAX];
};

/* Structure for GOTD_IMSG_INFO_CLIENT */
struct gotd_imsg_info_client {
	uid_t euid;
	gid_t egid;
	char repo_name[NAME_MAX];
	int is_writing;
	enum gotd_client_state state;
	size_t ncapabilities;

	/* Followed by ncapabilities GOTD_IMSG_CAPABILITY. */
};

/* Structure for GOTD_IMSG_LIST_REFS. */
struct gotd_imsg_list_refs {
	char repo_name[NAME_MAX];
	int client_is_reading; /* 1 if reading, 0 if writing */
};

/* Structure for GOTD_IMSG_LIST_REFS_INTERNAL. */
struct gotd_imsg_list_refs_internal {
	uint32_t client_id;
};

/* Structure for GOTD_IMSG_REFLIST. */
struct gotd_imsg_reflist {
	size_t nrefs;

	/* Followed by nrefs times of gotd_imsg_ref/gotd_imsg_symref data. */
} __attribute__((__packed__));

/* Structure for GOTD_IMSG_REF data. */
struct gotd_imsg_ref {
	uint8_t id[SHA1_DIGEST_LENGTH];
	size_t name_len;
	/* Followed by name_len data bytes. */
} __attribute__((__packed__));

/* Structure for GOTD_IMSG_SYMREF data. */
struct gotd_imsg_symref {
	size_t name_len;
	size_t target_len;
	uint8_t target_id[SHA1_DIGEST_LENGTH];

	/*
	 * Followed by name_len + target_len data bytes.
	 */
} __attribute__((__packed__));

/* Structure for GOTD_IMSG_CAPABILITIES data. */
struct gotd_imsg_capabilities {
	size_t ncapabilities;

	/*
	 * Followed by ncapabilities * GOTD_IMSG_CAPABILITY.
	 */
} __attribute__((__packed__));

/* Structure for GOTD_IMSG_CAPABILITY data. */
struct gotd_imsg_capability {
	size_t key_len;
	size_t value_len;

	/*
	 * Followed by key_len + value_len data bytes.
	 */
} __attribute__((__packed__));

/* Structure for GOTD_IMSG_WANT data. */
struct gotd_imsg_want {
	uint8_t object_id[SHA1_DIGEST_LENGTH];
	uint32_t client_id;
} __attribute__((__packed__));

/* Structure for GOTD_IMSG_HAVE data. */
struct gotd_imsg_have {
	uint8_t object_id[SHA1_DIGEST_LENGTH];
	uint32_t client_id;
} __attribute__((__packed__));

/* Structure for GOTD_IMSG_ACK data. */
struct gotd_imsg_ack {
	uint8_t object_id[SHA1_DIGEST_LENGTH];
	uint32_t client_id;
} __attribute__((__packed__));

/* Structure for GOTD_IMSG_NAK data. */
struct gotd_imsg_nak {
	uint8_t object_id[SHA1_DIGEST_LENGTH];
	uint32_t client_id;
} __attribute__((__packed__));

/* Structure for GOTD_IMSG_PACKFILE_STATUS data. */
struct gotd_imsg_packfile_status {
	size_t reason_len;

	/* Followed by reason_len data bytes. */
} __attribute__((__packed__));


/* Structure for GOTD_IMSG_REF_UPDATE data. */
struct gotd_imsg_ref_update {
	uint8_t old_id[SHA1_DIGEST_LENGTH];
	uint8_t new_id[SHA1_DIGEST_LENGTH];
	int ref_is_new;
	uint32_t client_id;
	size_t name_len;

	/* Followed by name_len data bytes. */
} __attribute__((__packed__));

/* Structure for GOTD_IMSG_REF_UPDATES_START data. */
struct gotd_imsg_ref_updates_start {
	int nref_updates;
	uint32_t client_id;

	/* Followed by nref_updates GOT_IMSG_REF_UPDATE_OK/NG messages. */
};

/* Structure for GOTD_IMSG_REF_UPDATE_OK data. */
struct gotd_imsg_ref_update_ok {
	uint8_t old_id[SHA1_DIGEST_LENGTH];
	uint8_t new_id[SHA1_DIGEST_LENGTH];
	int ref_is_new;
	uint32_t client_id;
	size_t name_len;

	/* Followed by name_len data bytes. */
} __attribute__((__packed__));

/* Structure for GOTD_IMSG_REF_UPDATE_NG data. */
struct gotd_imsg_ref_update_ng {
	uint8_t old_id[SHA1_DIGEST_LENGTH];
	uint8_t new_id[SHA1_DIGEST_LENGTH];
	uint32_t client_id;
	size_t name_len;
	size_t reason_len;

	/* Followed by name_len + reason_len data bytes. */
} __attribute__((__packed__));

/* Structure for GOTD_IMSG_SEND_PACKFILE data. */
struct gotd_imsg_send_packfile {
	uint32_t client_id;
	int report_progress;

	/* delta cache file is sent as a file descriptor */

	/* followed by two GOTD_IMSG_PACKFILE_PIPE messages */
};

/* Structure for GOTD_IMSG_RECV_PACKFILE data. */
struct gotd_imsg_recv_packfile {
	uint32_t client_id;
	int report_status;

	/* pack destination temp file is sent as a file descriptor */
};

/* Structure for GOTD_IMSG_PACKFILE_PIPE data. */
struct gotd_imsg_packfile_pipe {
	uint32_t client_id;
};

/* Structure for GOTD_IMSG_PACKIDX_FILE data. */
struct gotd_imsg_packidx_file {
	uint32_t client_id;
};


/*
 * Structure for GOTD_IMSG_PACKFILE_PROGRESS and
 * GOTD_IMSG_PACKFILE_READY data.
 */
struct gotd_imsg_packfile_progress {
	uint32_t client_id;
	int ncolored;
	int nfound;
	int ntrees;
	off_t packfile_size;
	int ncommits;
	int nobj_total;
	int nobj_deltify;
	int nobj_written;
};

/* Structure for GOTD_IMSG_PACKFILE_INSTALL. */
struct gotd_imsg_packfile_install {
	uint32_t client_id;
	uint8_t pack_sha1[SHA1_DIGEST_LENGTH];
};

/* Structure for GOTD_IMSG_PACKFILE_DONE data. */
struct gotd_imsg_packfile_done {
	uint32_t client_id;
};

/* Structure for GOTD_IMSG_DISCONNECT data. */
struct gotd_imsg_disconnect {
	uint32_t client_id;
};

int parse_config(const char *, enum gotd_procid, struct gotd *);

/* imsg.c */
const struct got_error *gotd_imsg_flush(struct imsgbuf *);
const struct got_error *gotd_imsg_recv(struct imsg *, struct imsgbuf *, size_t);
const struct got_error *gotd_imsg_poll_recv(struct imsg *, struct imsgbuf *,
    size_t);
const struct got_error *gotd_imsg_recv_error(uint32_t *client_id,
    struct imsg *imsg);
int gotd_imsg_send_error(struct imsgbuf *ibuf, uint32_t, uint32_t,
    const struct got_error *);
int gotd_imsg_send_error_event(struct gotd_imsgev *, uint32_t, uint32_t,
    const struct got_error *);
void gotd_imsg_event_add(struct gotd_imsgev *);
int gotd_imsg_compose_event(struct gotd_imsgev *, uint16_t, uint32_t, int,
    void *, uint16_t);
int gotd_imsg_forward(struct gotd_imsgev *, struct imsg *, int);

void gotd_imsg_send_ack(struct got_object_id *, struct imsgbuf *,
    uint32_t, pid_t);
void gotd_imsg_send_nak(struct got_object_id *, struct imsgbuf *,
    uint32_t, pid_t);
