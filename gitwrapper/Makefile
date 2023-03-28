.PATH:${.CURDIR}/../lib
.PATH:${.CURDIR}/../gotd

.include "../got-version.mk"

.if ${GOT_RELEASE} == "Yes"
BINDIR ?=	${PREFIX}/bin
.endif

PROG=		gitwrapper
SRCS=		gitwrapper.c parse.y log.c serve.c auth.c listen.c pkt.c \
		error.c gitproto.c hash.c reference.c object.c object_parse.c \
		path.c object_idset.c object_create.c inflate.c opentemp.c \
		lockfile.c repository.c gotconfig.c pack.c bloom.c buf.c \
		object_cache.c privsep_stub.c pollfd.c imsg.c \
		reference_parse.c object_open_io.c sigs.c deflate.c \
		read_gotconfig.c read_gitconfig.c delta_cache.c delta.c \
		murmurhash2.c date.c gitconfig.c

CLEANFILES = parse.h

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
