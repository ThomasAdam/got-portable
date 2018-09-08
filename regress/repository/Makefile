.PATH:${.CURDIR}/../../lib

PROG = repository_test
SRCS = path.c repository.c error.c reference.c object.c object_idcache.c \
	object_idset.c object_parse.c opentemp.c sha1.c diff.c diffreg.c \
	pack.c privsep.c delta.c fileindex.c worktree.c inflate.c \
	repository_test.c

GOT_LIBEXECDIR = ${HOME}/bin
CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib \
	-DGOT_LIBEXECDIR=${GOT_LIBEXECDIR}
LDADD = -lutil -lz
DEBUG = -O0 -g
CFLAGS += -Werror -Wall -Wstrict-prototypes -Wunused-variable
#CFLAGS += -DGOT_PACK_NO_MMAP
#CFLAGS += -DGOT_NO_OBJ_CACHE

NOMAN = yes

.include <bsd.regress.mk>
