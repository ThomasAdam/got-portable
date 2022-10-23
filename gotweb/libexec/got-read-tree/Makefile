
.include "../../../got-version.mk"
.include "../Makefile.inc"

PROG=		got-read-tree
SRCS=		got-read-tree.c error.c inflate.c object_parse.c \
		path.c privsep.c sha1.c pollfd.c

CPPFLAGS = -I${.CURDIR}/../../../include -I${.CURDIR}/../../../lib
LDADD = -lutil -lz
DPADD = ${LIBZ} ${LIBUTIL}
LDSTATIC = ${STATIC}

.PATH:	${.CURDIR}/../../../lib ${.CURDIR}/../../../libexec/got-read-tree

.include <bsd.prog.mk>
