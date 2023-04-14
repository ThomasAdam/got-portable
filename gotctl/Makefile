.PATH:${.CURDIR}/../lib ${.CURDIR}/../gotd

.include "../got-version.mk"

PROG=		gotctl
SRCS=		gotctl.c error.c imsg.c object_qid.c path.c \
		pollfd.c hash.c

MAN =		${PROG}.8

CPPFLAGS = -I${.CURDIR}/../include -I${.CURDIR}/../lib -I${.CURDIR}/../gotd

.if defined(PROFILE)
LDADD = -lutil_p -lz_p -lm_p -lc_p -levent_p
.else
LDADD = -lutil -lz -lm -levent
.endif
DPADD = ${LIBZ} ${LIBUTIL}

.if ${GOT_RELEASE} != "Yes"
NOMAN = Yes
.else
BINDIR = ${PREFIX}/sbin
.endif

realinstall:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} \
	-m ${BINMODE} ${PROG} ${BINDIR}/${PROG}

.include <bsd.prog.mk>
