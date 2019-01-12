.PATH:${.CURDIR}/../../lib

PROG = path_test
SRCS = error.c path.c sha1.c path_test.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib
LDADD = -lutil -lz

NOMAN = yes

.include <bsd.regress.mk>
