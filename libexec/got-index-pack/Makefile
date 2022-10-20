.PATH:${.CURDIR}/../../lib

.include "../../got-version.mk"

PROG=		got-index-pack
SRCS=		got-index-pack.c error.c inflate.c object_parse.c object_idset.c \
		delta_cache.c delta.c pack.c path.c privsep.c sha1.c ratelimit.c \
		pack_index.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib

.if defined(PROFILE)
LDADD = -lutil_p -lz_p
.else
LDADD = -lutil -lz
.endif

DPADD = ${LIBZ} ${LIBUTIL}

.include <bsd.prog.mk>
