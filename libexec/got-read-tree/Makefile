.PATH:${.CURDIR}/../../lib

PROG=		got-read-tree
SRCS=		got-read-tree.c error.c inflate.c object_parse.c \
		path.c privsep.c sha1.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib
LDADD = -lutil -lz
DPADD = ${LIBZ} ${LIBUTIL}

# For now, default to installing binary in ~/bin
GROUP!=id -g -n
install:
	${INSTALL} ${INSTALL_COPY} -o ${USER} -g ${GROUP} \
	-m ${BINMODE} ${PROG} ${GOT_LIBEXECDIR}/${PROG}

# Don't install man pages yet
NOMAN = Yes

.include <bsd.prog.mk>
