.PATH:${.CURDIR}/../lib

PROG=		got
SRCS=		got.c blame.c commit_graph.c delta.c diff.c diffoffset.c \
		diffreg.c error.c fileindex.c object.c object_idcache.c \
		object_idset.c opentemp.c path.c pack.c privsep.c reference.c \
		repository.c sha1.c worktree.c inflate.c

CPPFLAGS = -I${.CURDIR}/../include -I${.CURDIR}/../lib
LDADD = -lutil -lz
DPADD = ${LIBZ} ${LIBUTIL}
.if defined(PROFILE)
CC = gcc
CPPFLAGS += -DPROFILE
DEBUG = -O0 -pg
.else
DEBUG = -O0 -g
.endif
CFLAGS += -Werror -Wall -Wstrict-prototypes -Wunused-variable
#CPLAGS += -DGOT_PACK_NO_MMAP
#CFLAGS += -DGOT_NO_OBJ_CACHE

# For now, default to installing binary in ~/bin
GROUP!=id -g -n
install:
	${INSTALL} ${INSTALL_COPY} -o ${USER} -g ${GROUP} \
	-m ${BINMODE} ${PROG} ${HOME}/bin/${PROG}

# Don't install man pages yet
NOMAN = Yes

.include <bsd.prog.mk>
