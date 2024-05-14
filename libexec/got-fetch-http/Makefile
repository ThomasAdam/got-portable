.PATH:${.CURDIR}/../../lib

.include "../../got-version.mk"

PROG=		got-fetch-http
SRCS=		got-fetch-http.c bufio.c hash.c error.c inflate.c pkt.c \
		pollfd.c path.c

CPPFLAGS= -I${.CURDIR}/../../include -I${.CURDIR}/../../lib

.if defined(PROFILE)
LDADD=	-lutil_p -lz_p -ltls_p -lcrypto_p -lssl_p
.else
LDADD=	-lutil -lz -ltls
.endif

DPADD=	${LIBZ} ${LIBUTIL} ${LIBTLS}

.include <bsd.prog.mk>
