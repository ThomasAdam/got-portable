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

/* Well-known reference names. */
#define GOT_REF_HEAD		"HEAD"
#define GOT_REF_ORIG_HEAD	"ORIG_HEAD"
#define GOT_REF_MERGE_HEAD	"MERGE_HEAD"

const struct got_error *
got_ref_open(struct got_reference **, const char *, const char *);

void got_ref_close(struct got_reference *);

