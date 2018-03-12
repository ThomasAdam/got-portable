.PATH:${.CURDIR}/../../lib

PROG = repository_test
SRCS = path.c repository.c error.c refs.c object.c sha1.c diff.c \
	diffreg.c pack.c delta.c zbuf.c repository_test.c

CPPFLAGS = -I${.CURDIR}/../../include
LDADD = -lutil -lz
DEBUG = -O0 -g
CFLAGS = -Werror -Wall -Wstrict-prototypes -Wunused-variable

NOMAN = yes

.include <bsd.regress.mk>
