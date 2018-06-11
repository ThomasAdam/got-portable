.PATH:${.CURDIR}/../lib

PROG=		tog
SRCS=		tog.c commit_graph.c delta.c diff.c diffreg.c error.c \
		fileindex.c object.c object_idset.c opentemp.c path.c \
		pack.c privsep.c reference.c repository.c sha1.c worktree.c \
		utf8.c zbuf.c

CPPFLAGS = -I${.CURDIR}/../include -I${.CURDIR}/../lib
LDADD = -lpanel -lncursesw -lutil -lz
DPADD = ${LIBZ} ${LIBUTIL}
.if defined(PROFILE)
CC = gcc
CPPFLAGS += -DPROFILE
DEBUG = -O0 -pg
.else
DEBUG = -O0 -g
.endif
CFLAGS += -Werror -Wall -Wstrict-prototypes -Wunused-variable

# For now, default to installing binary in ~/bin
GROUP!=id -g -n
install:
	${INSTALL} ${INSTALL_COPY} -o ${USER} -g ${GROUP} \
	-m ${BINMODE} ${PROG} ${HOME}/bin/${PROG}

# Don't install man pages yet
NOMAN = Yes

.include <bsd.prog.mk>
