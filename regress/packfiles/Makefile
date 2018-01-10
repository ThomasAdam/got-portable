.PATH:${.CURDIR}/../../lib

PROG = packfile_test
SRCS = error.c pack.c packfile_test.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib
LDADD = 
DEBUG = -O0 -g

NOMAN = yes

.include <bsd.regress.mk>
