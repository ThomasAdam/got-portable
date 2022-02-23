.PATH:${.CURDIR}/../../lib

.include "../../got-version.mk"

PROG=		got-index-pack
SRCS=		got-index-pack.c error.c inflate.c object_parse.c object_idset.c \
		delta_cache.c delta.c pack.c path.c privsep.c sha1.c ratelimit.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib
LDADD = -lutil -lz
DPADD = ${LIBZ} ${LIBUTIL}

.include <bsd.prog.mk>
