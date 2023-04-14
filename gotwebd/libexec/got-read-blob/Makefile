.include "../../../got-version.mk"
.include "../Makefile.inc"

PROG=		got-read-blob
SRCS=		got-read-blob.c error.c inflate.c object_parse.c \
		path.c privsep.c hash.c pollfd.c object_qid.c

CPPFLAGS = -I${.CURDIR}/../../../include -I${.CURDIR}/../../../lib
LDADD = -lutil -lz
DPADD = ${LIBZ} ${LIBUTIL}
LDSTATIC = ${STATIC}

.PATH:	${.CURDIR}/../../../lib ${.CURDIR}/../../../libexec/got-read-blob

.include <bsd.prog.mk>
