.PATH:${.CURDIR}/../lib

PROG=		got
SRCS=		got.c delta.c error.c fileindex.c object.c path.c pack.c \
		refs.c repository.c sha1.c worktree.c zbuf.c

CPPFLAGS = -I${.CURDIR}/../include -I${.CURDIR}/../lib
LDADD = -lutil -lz
DPADD = ${LIBZ} ${LIBUTIL}
CC = gcc
DEBUG = -O0 -pg
CPPFLAGS += -DPROFILE
CFLAGS += -Werror -Wall -Wstrict-prototypes -Wunused-variable

# For now, default to installing binary in ~/bin
GROUP!=id -g -n
install:
	${INSTALL} ${INSTALL_COPY} -o ${USER} -g ${GROUP} \
	-m ${BINMODE} ${PROG} ${HOME}/bin/${PROG}

# Don't install man pages yet
NOMAN = Yes

.include <bsd.prog.mk>
