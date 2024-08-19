.PATH:${.CURDIR}/../..
.PATH:${.CURDIR}/../../../lib

.include "../../../got-version.mk"

PROG=	got-notify-http
SRCS=	got-notify-http.c bufio.c opentemp.c pollfd.c error.c hash.c log.c

CPPFLAGS= -I${.CURDIR}/../../../include -I${.CURDIR}/../../../lib -I${.CURDIR}/../..

DPADD=	${LIBTLS} ${LIBCRYPTO}
LDADD=	-ltls -lcrypto

.include <bsd.prog.mk>
