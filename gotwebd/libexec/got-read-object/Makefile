.include "../../../got-version.mk"
.include "../Makefile.inc"

PROG=		got-read-object
SRCS=		got-read-object.c error.c inflate.c object_parse.c \
		path.c privsep.c hash.c pollfd.c

CPPFLAGS = -I${.CURDIR}/../../../include -I${.CURDIR}/../../../lib
LDADD = -lutil -lz
DPADD = ${LIBZ} ${LIBUTIL}
LDSTATIC = ${STATIC}

.PATH:	${.CURDIR}/../../../lib ${.CURDIR}/../../../libexec/got-read-object

.include <bsd.prog.mk>
