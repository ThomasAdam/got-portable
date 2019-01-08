.PATH:${.CURDIR}/../lib

PROG=		got
SRCS=		got.c blame.c commit_graph.c delta.c diff.c diffoffset.c \
		diffreg.c error.c fileindex.c object.c object_cache.c \
		object_idset.c object_parse.c opentemp.c path.c pack.c \
		privsep.c reference.c repository.c sha1.c worktree.c \
		inflate.c

CPPFLAGS = -I${.CURDIR}/../include -I${.CURDIR}/../lib \
	-DGOT_LIBEXECDIR=${GOT_LIBEXECDIR}
LDADD = -lutil -lz
DPADD = ${LIBZ} ${LIBUTIL}

# For now, default to installing binary in ~/bin
GROUP!=id -g -n
install:
	${INSTALL} ${INSTALL_COPY} -o ${USER} -g ${GROUP} \
	-m ${BINMODE} ${PROG} ${HOME}/bin/${PROG}

# Don't install man pages yet
NOMAN = Yes

.include <bsd.prog.mk>
