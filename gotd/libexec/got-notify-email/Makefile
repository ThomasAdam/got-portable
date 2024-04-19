.PATH:${.CURDIR}/../..
.PATH:${.CURDIR}/../../../lib

.include "../../../got-version.mk"

PROG=		got-notify-email
SRCS=		got-notify-email.c pollfd.c error.c hash.c log.c


CPPFLAGS = -I${.CURDIR}/../../../include -I${.CURDIR}/../../../lib -I${.CURDIR}/../..

.include <bsd.prog.mk>
