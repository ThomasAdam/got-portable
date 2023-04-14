.include "../../../got-version.mk"
.include "../Makefile.inc"

PROG=		got-read-gotconfig
SRCS=		got-read-gotconfig.c error.c inflate.c object_parse.c \
		path.c privsep.c hash.c parse.y pollfd.c object_qid.c

CPPFLAGS = -I${.CURDIR}/../../../include -I${.CURDIR}/../../../lib \
	-I${.CURDIR}/../../../libexec/got-read-gotconfig
YFLAGS =
LDADD = -lutil -lz
DPADD = ${LIBZ} ${LIBUTIL}
LDSTATIC = ${STATIC}

CLEANFILES = parse.h

.PATH:	${.CURDIR}/../../../lib ${.CURDIR}/../../../libexec/got-read-gotconfig

.include <bsd.prog.mk>
