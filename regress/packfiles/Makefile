.PATH:${.CURDIR}/../../lib

PROG = packfile_test
SRCS = error.c pack.c repository.c object.c path.c sha1.c packfile_test.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib
LDADD = -lutil -lz
DEBUG = -O0 -g

NOMAN = yes

.include <bsd.regress.mk>
