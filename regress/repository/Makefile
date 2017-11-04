.PATH:${.CURDIR}/../../lib

PROG = repository_test
SRCS = path.c repository.c error.c refs.c repository_test.c

CPPFLAGS = -I${.CURDIR}/../../include
LDADD = -lutil

NOMAN = yes

.include <bsd.regress.mk>
