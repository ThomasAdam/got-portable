.PATH:${.CURDIR}/../../lib

.include "../../got-version.mk"

PROG=		got-fetch-pack
SRCS=		got-fetch-pack.c error.c inflate.c object_parse.c \
		path.c privsep.c sha1.c pkt.c gitproto.c ratelimit.c \
		pollfd.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib

.if defined(PROFILE)
LDADD = -lutil_p -lz_p
.else
LDADD = -lutil -lz
.endif
DPADD = ${LIBZ} ${LIBUTIL}

.include <bsd.prog.mk>
