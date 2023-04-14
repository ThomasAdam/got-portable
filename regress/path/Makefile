.PATH:${.CURDIR}/../../lib

PROG = path_test
SRCS = error.c path.c hash.c path_test.c object_parse.c inflate.c pollfd.c \
	object_qid.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib
LDADD = -lutil -lz

NOMAN = yes

run-regress-path_test:
	${.OBJDIR}/path_test -q

.include <bsd.regress.mk>
