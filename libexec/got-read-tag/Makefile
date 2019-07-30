.PATH:${.CURDIR}/../../lib

.include "../../got-version.mk"

PROG=		got-read-tag
SRCS=		got-read-tag.c error.c inflate.c object_parse.c \
		path.c privsep.c sha1.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib
LDADD = -lutil -lz
DPADD = ${LIBZ} ${LIBUTIL}

.include <bsd.prog.mk>
