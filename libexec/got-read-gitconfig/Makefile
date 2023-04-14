.PATH:${.CURDIR}/../../lib

.include "../../got-version.mk"

PROG=		got-read-gitconfig
SRCS=		got-read-gitconfig.c error.c inflate.c object_parse.c \
		path.c privsep.c hash.c gitconfig.c pollfd.c object_qid.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib

.if defined(PROFILE)
LDADD = -lutil_p -lz_p
.else
LDADD = -lutil -lz
.endif

DPADD = ${LIBZ} ${LIBUTIL}

.include <bsd.prog.mk>
