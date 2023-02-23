.include "../../../got-version.mk"
.include "../Makefile.inc"

PROG=		got-read-gitconfig
SRCS=		got-read-gitconfig.c error.c inflate.c object_parse.c \
		path.c privsep.c hash.c gitconfig.c pollfd.c

CPPFLAGS = -I${.CURDIR}/../../../include -I${.CURDIR}/../../../lib
LDADD = -lutil -lz
DPADD = ${LIBZ} ${LIBUTIL}
LDSTATIC = ${STATIC}

.PATH:	${.CURDIR}/../../../lib ${.CURDIR}/../../../libexec/got-read-gitconfig

.include <bsd.prog.mk>
