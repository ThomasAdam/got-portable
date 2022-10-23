
.include "../../../got-version.mk"
.include "../Makefile.inc"

PROG=		got-read-pack
SRCS=		got-read-pack.c delta.c error.c inflate.c object_cache.c \
		object_idset.c object_parse.c opentemp.c pack.c path.c \
		privsep.c sha1.c delta_cache.c pollfd.c

CPPFLAGS = -I${.CURDIR}/../../../include -I${.CURDIR}/../../../lib
LDADD = -lutil -lz
DPADD = ${LIBZ} ${LIBUTIL}
LDSTATIC = ${STATIC}

.PATH:	${.CURDIR}/../../../lib ${.CURDIR}/../../../libexec/got-read-pack

.include <bsd.prog.mk>
