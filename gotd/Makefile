.PATH:${.CURDIR}/../lib

.include "../got-version.mk"

.if ${GOT_RELEASE} == "Yes"
BINDIR ?=	${PREFIX}/sbin
.endif

PROG=		gotd
SRCS=		gotd.c auth.c repo_read.c repo_write.c log.c privsep_stub.c \
		listen.c imsg.c parse.y pack_create.c ratelimit.c deltify.c \
		bloom.c buf.c date.c deflate.c delta.c delta_cache.c error.c \
		gitconfig.c gotconfig.c inflate.c lockfile.c murmurhash2.c \
		object.c object_cache.c object_create.c object_idset.c \
		object_open_io.c object_parse.c opentemp.c pack.c path.c \
		read_gitconfig.c read_gotconfig.c reference.c repository.c  \
		hash.c sigs.c pack_create_io.c pollfd.c reference_parse.c \
		repo_imsg.c pack_index.c session.c object_qid.c

CLEANFILES = parse.h

MAN =		${PROG}.conf.5 ${PROG}.8

CPPFLAGS = -I${.CURDIR}/../include -I${.CURDIR}/../lib -I${.CURDIR}
YFLAGS =

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
