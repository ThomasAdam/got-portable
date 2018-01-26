.PATH:${.CURDIR}/../../lib

PROG = delta_test
SRCS = delta.c error.c delta_test.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib
LDADD = -lz
DEBUG = -O0 -g
CFLAGS += -Werror

NOMAN = yes

.include <bsd.regress.mk>
