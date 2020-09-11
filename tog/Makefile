.PATH:${.CURDIR}/../lib

.include "../got-version.mk"

PROG=		tog
SRCS=		tog.c blame.c commit_graph.c delta.c diff.c \
		diffreg.c error.c fileindex.c object.c object_cache.c \
		object_idset.c object_parse.c opentemp.c path.c pack.c \
		privsep.c reference.c repository.c sha1.c worktree.c \
		utf8.c inflate.c buf.c rcsutil.c diff3.c \
		lockfile.c deflate.c object_create.c delta_cache.c \
		gotconfig.c
MAN =		${PROG}.1

CPPFLAGS = -I${.CURDIR}/../include -I${.CURDIR}/../lib

.if defined(PROFILE)
LDADD = -lpanel_p -lncursesw_p -lutil_p -lz_p -lpthread_p -lc_p
.else
LDADD = -lpanel -lncursesw -lutil -lz -lpthread
.endif
DPADD = ${LIBZ} ${LIBUTIL}

.if ${GOT_RELEASE} != "Yes"
NOMAN = Yes
.endif

realinstall:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} \
	-m ${BINMODE} ${PROG} ${BINDIR}/${PROG}

.include <bsd.prog.mk>
