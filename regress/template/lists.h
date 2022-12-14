#include <sys/queue.h>

TAILQ_HEAD(tailhead, entry);
struct entry {
	char	*text;
	TAILQ_ENTRY(entry) entries;
};
