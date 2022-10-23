.PATH:${.CURDIR}/../../lib

PROG = delta_test
SRCS = delta.c error.c opentemp.c path.c inflate.c sha1.c delta_test.c pollfd.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib
LDADD = -lz

NOMAN = yes

run-regress-delta_test:
	${.OBJDIR}/delta_test -q

.include <bsd.regress.mk>
