.PATH:${.CURDIR}/../lib ${.CURDIR}/../gotd

.include "../got-version.mk"

PREFIX ?=	/usr/local
BINDIR ?=	${PREFIX}/bin

PROG=		gotsh
SRCS=		gotsh.c error.c pkt.c sha1.c serve.c path.c gitproto.c \
		imsg.c pollfd.c reference_parse.c

MAN =		${PROG}.1

CPPFLAGS = -I${.CURDIR}/../include -I${.CURDIR}/../lib -I${.CURDIR}/../gotd

.if defined(PROFILE)
LDADD = -lutil_p -lz_p -lm_p -lc_p -levent_p
.else
LDADD = -lutil -lz -lm -levent
.endif
DPADD = ${LIBZ} ${LIBUTIL}

.if ${GOT_RELEASE} != "Yes"
NOMAN = Yes
.endif

realinstall:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} \
	-m ${BINMODE} ${PROG} ${BINDIR}/${PROG}

.include <bsd.prog.mk>
