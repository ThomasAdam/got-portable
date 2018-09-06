.PATH:${.CURDIR}/../../lib

PROG = worktree_test
SRCS = worktree.c repository.c object.c object_idcache.c object_idset.c \
	object_parse.c opentemp.c path.c error.c reference.c sha1.c pack.c \
	privsep.c delta.c inflate.c fileindex.c worktree_test.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib
LDADD = -lutil -lz
DEBUG = -O0 -g
CFLAGS += -Werror -Wall -Wstrict-prototypes -Wunused-variable
#CFLAGS += -DGOT_PACK_NO_MMAP
#CFLAGS += -DGOT_NO_OBJ_CACHE

NOMAN = yes

.include <bsd.regress.mk>
