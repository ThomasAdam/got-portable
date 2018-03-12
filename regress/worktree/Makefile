.PATH:${.CURDIR}/../../lib

PROG = worktree_test
SRCS = worktree.c repository.c object.c path.c error.c refs.c sha1.c pack.c \
	delta.c zbuf.c fileindex.c worktree_test.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib
LDADD = -lutil -lz
DEBUG = -O0 -g
CFLAGS = -Werror -Wall -Wstrict-prototypes -Wunused-variable

NOMAN = yes

.include <bsd.regress.mk>
