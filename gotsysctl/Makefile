.PATH:${.CURDIR}/../lib ${.CURDIR}/../gotsysd

.include "../got-version.mk"

PROG=	gotsysctl
SRCS=	gotsysctl.c error.c pollfd.c hash.c imsg.c

MAN =		${PROG}.8

CPPFLAGS = -I${.CURDIR}/../include -I${.CURDIR}/../lib -I${.CURDIR}/../gotsysd

.if defined(PROFILE)
LDADD = -lutil_p -lc_p -levent_p
.else
LDADD = -lutil -levent
.endif
DPADD = ${LIBUTIL} ${LIBEVENT}

.if ${GOT_RELEASE} != "Yes"
NOMAN = Yes
.endif

realinstall:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} \
	-m ${BINMODE} ${PROG} ${BINDIR}/${PROG}

.include <bsd.prog.mk>
