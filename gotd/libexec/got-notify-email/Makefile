.PATH:${.CURDIR}/../..
.PATH:${.CURDIR}/../../../lib

.include "../../../got-version.mk"

PROG=		got-notify-email
SRCS=		got-notify-email.c pollfd.c error.c hash.c


CPPFLAGS = -I${.CURDIR}/../../../include -I${.CURDIR}/../../../lib

.if defined(PROFILE)
LDADD = -lutil_p -lz_p -lm_p
.else
LDADD = -lutil -lz -lm
.endif

DPADD = ${LIBZ} ${LIBUTIL}

.include <bsd.prog.mk>
