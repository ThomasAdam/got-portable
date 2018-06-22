.PATH:${.CURDIR}/../../lib

PROG = repository_test
SRCS = path.c repository.c error.c reference.c object.c object_idset.c \
	opentemp.c sha1.c diff.c diffreg.c pack.c privsep.c delta.c \
	fileindex.c worktree.c zbuf.c repository_test.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib
LDADD = -lutil -lz
DEBUG = -O0 -g
CFLAGS += -Werror -Wall -Wstrict-prototypes -Wunused-variable

NOMAN = yes

.include <bsd.regress.mk>
