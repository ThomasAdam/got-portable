.PATH:${.CURDIR}/../..
.PATH:${.CURDIR}/../../../lib

.include "../../../got-version.mk"

PROG=	got-notify-http
SRCS=	got-notify-http.c bufio.c opentemp.c pollfd.c error.c hash.c log.c

CPPFLAGS= -I${.CURDIR}/../../../include -I${.CURDIR}/../../../lib -I${.CURDIR}/../..

DPADD=	${LIBTLS}
LDADD=	-ltls

.include <bsd.prog.mk>
