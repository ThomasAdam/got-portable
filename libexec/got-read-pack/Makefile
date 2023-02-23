.PATH:${.CURDIR}/../../lib

.include "../../got-version.mk"

PROG=		got-read-pack
SRCS=		got-read-pack.c delta.c error.c inflate.c object_cache.c \
		object_idset.c object_parse.c opentemp.c pack.c path.c \
		privsep.c hash.c delta_cache.c pollfd.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib

.if defined(PROFILE)
LDADD = -lutil_p -lz_p
.else
LDADD = -lutil -lz
.endif

DPADD = ${LIBZ} ${LIBUTIL}

.include <bsd.prog.mk>
