.PATH:${.CURDIR}/../../lib

PROG = deltify_test
SRCS = deltify.c error.c opentemp.c hash.c deltify_test.c murmurhash2.c \
	object_parse.c inflate.c path.c pollfd.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib
LDADD = -lz

NOMAN = yes

run-regress-deltify_test:
	${.OBJDIR}/deltify_test -q

.include <bsd.regress.mk>
