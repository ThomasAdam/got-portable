.PATH:${.CURDIR}/../../lib

.include "../../got-version.mk"

PROG=		got-read-blob
SRCS=		got-read-blob.c error.c inflate.c object_parse.c \
		path.c privsep.c sha1.c pollfd.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib

.if defined(PROFILE)
LDADD = -lutil_p -lz_p
.else
LDADD = -lutil -lz
.endif

DPADD = ${LIBZ} ${LIBUTIL}

.include <bsd.prog.mk>
