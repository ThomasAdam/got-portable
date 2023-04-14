.PATH:${.CURDIR}/../../lib

.include "../../got-version.mk"

PROG=		got-read-gotconfig
SRCS=		got-read-gotconfig.c error.c inflate.c object_parse.c \
		path.c privsep.c hash.c parse.y pollfd.c object_qid.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib -I${.CURDIR}
YFLAGS =

CLEANFILES = parse.h

.if defined(PROFILE)
LDADD = -lutil_p -lz_p
.else
LDADD = -lutil -lz
.endif

DPADD = ${LIBZ} ${LIBUTIL}

.include <bsd.prog.mk>
