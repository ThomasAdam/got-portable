.PATH:${.CURDIR}/../../lib

.include "../../got-version.mk"

PROG=		got-read-gotconfig
SRCS=		got-read-gotconfig.c error.c inflate.c object_parse.c \
		path.c privsep.c sha1.c parse.y

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib -I${.CURDIR}
LDADD = -lutil -lz
DPADD = ${LIBZ} ${LIBUTIL}

.include <bsd.prog.mk>
