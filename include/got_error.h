
/* Error codes */
#define GOT_ERR_UNKNOWN		0x0000
#define GOT_ERR_NO_MEM		0x0001
#define GOT_ERR_NOT_GIT_REPO	0x0002
#define GOT_ERR_NOT_ABSPATH	0x0003
#define GOT_ERR_BAD_PATH	0x0004
#define GOT_ERR_NOT_REF		0x0005

static const struct got_error {
	int code;
	const char *msg;
} got_errors[] = {
	{ GOT_ERR_UNKNOWN,	"unknown error" },
	{ GOT_ERR_NO_MEM,	"out of memory" },
	{ GOT_ERR_NOT_GIT_REPO, "no git repository found" },
	{ GOT_ERR_NOT_ABSPATH,	"absolute path expected" },
	{ GOT_ERR_BAD_PATH,	"bad path" },
	{ GOT_ERR_NOT_REF,	"no such reference found" },
};

const struct got_error * got_error(int code);
