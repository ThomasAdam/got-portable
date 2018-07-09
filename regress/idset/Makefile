.PATH:${.CURDIR}/../../lib

PROG = idset_test
SRCS = error.c object.c privsep.c sha1.c pack.c inflate.c path.c opentemp.c \
	delta.c repository.c reference.c worktree.c fileindex.c \
	object_idcache.c object_idset.c idset_test.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib
LDADD = -lutil -lz
DEBUG = -O0 -g
CFLAGS += -Werror -Wall -Wstrict-prototypes -Wunused-variable

NOMAN = yes

.include <bsd.regress.mk>
