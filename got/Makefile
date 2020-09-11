.PATH:${.CURDIR}/../lib

.include "../got-version.mk"

PROG=		got
SRCS=		got.c blame.c commit_graph.c delta.c diff.c \
		diffreg.c error.c fileindex.c object.c object_cache.c \
		object_idset.c object_parse.c opentemp.c path.c pack.c \
		privsep.c reference.c repository.c sha1.c worktree.c \
		inflate.c buf.c rcsutil.c diff3.c lockfile.c \
		deflate.c object_create.c delta_cache.c fetch.c \
		gotconfig.c
MAN =		${PROG}.1 got-worktree.5 git-repository.5

CPPFLAGS = -I${.CURDIR}/../include -I${.CURDIR}/../lib

.if defined(PROFILE)
LDADD = -lutil_p -lz_p -lc_p
.else
LDADD = -lutil -lz
.endif
DPADD = ${LIBZ} ${LIBUTIL}

.if ${GOT_RELEASE} != "Yes"
NOMAN = Yes
.endif

realinstall:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} \
	-m ${BINMODE} ${PROG} ${BINDIR}/${PROG}

dist:
	mkdir ../got-${GOT_VERSION}/got
	cp ${SRCS} ${MAN} ../got-${GOT_VERSION}/got

.include <bsd.prog.mk>
