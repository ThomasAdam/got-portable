.PATH:${.CURDIR}/../../lib

.include "../../got-version.mk"

PROG=		got-send-pack
SRCS=		got-send-pack.c error.c inflate.c object_parse.c \
		path.c privsep.c sha1.c pkt.c gitproto.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib
LDADD = -lutil -lz
DPADD = ${LIBZ} ${LIBUTIL}

.include <bsd.prog.mk>
