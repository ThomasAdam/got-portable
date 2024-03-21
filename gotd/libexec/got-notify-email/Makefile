.PATH:${.CURDIR}/../..
.PATH:${.CURDIR}/../../../lib

.include "../../../got-version.mk"

PROG=		got-notify-email
SRCS=		got-notify-email.c pollfd.c error.c hash.c


CPPFLAGS = -I${.CURDIR}/../../../include -I${.CURDIR}/../../../lib

.include <bsd.prog.mk>
