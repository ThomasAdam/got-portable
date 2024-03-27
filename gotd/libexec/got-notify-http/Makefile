.PATH:${.CURDIR}/../..
.PATH:${.CURDIR}/../../../lib

.include "../../../got-version.mk"

PROG=	got-notify-http
SRCS=	got-notify-http.c bufio.c opentemp.c pollfd.c error.c hash.c

CPPFLAGS= -I${.CURDIR}/../../../include -I${.CURDIR}/../../../lib

DPADD=	${LIBTLS}
LDADD=	-ltls

.include <bsd.prog.mk>
