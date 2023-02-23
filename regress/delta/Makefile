.PATH:${.CURDIR}/../../lib

PROG = delta_test
SRCS = delta.c error.c opentemp.c path.c inflate.c hash.c delta_test.c \
	pollfd.c object_parse.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib
LDADD = -lz

NOMAN = yes

run-regress-delta_test:
	${.OBJDIR}/delta_test -q

.include <bsd.regress.mk>
