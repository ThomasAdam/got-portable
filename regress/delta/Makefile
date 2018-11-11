.PATH:${.CURDIR}/../../lib

PROG = delta_test
SRCS = delta.c error.c opentemp.c path.c inflate.c sha1.c delta_test.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib
LDADD = -lz

NOMAN = yes

.include <bsd.regress.mk>
