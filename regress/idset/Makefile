.PATH:${.CURDIR}/../../lib

PROG = idset_test
SRCS = error.c hash.c object_idset.c inflate.c path.c object_parse.c \
	idset_test.c pollfd.c object_qid.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib
LDADD = -lutil -lz

NOMAN = yes

run-regress-idset_test:
	${.OBJDIR}/idset_test -q

.include <bsd.regress.mk>
