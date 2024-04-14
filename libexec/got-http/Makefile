.PATH:${.CURDIR}/../../lib

.include "../../got-version.mk"

PROG=		got-http
SRCS=		got-http.c hash.c error.c inflate.c pollfd.c

CPPFLAGS= -I${.CURDIR}/../../include -I${.CURDIR}/../../lib

.if defined(PROFILE)
LDADD=	-lutil_p -lz_p -ltls_p
.else
LDADD=	-lutil -lz -ltls
.endif

DPADD=	${LIBZ} ${LIBUTIL} ${LIBTLS}

.include <bsd.prog.mk>
