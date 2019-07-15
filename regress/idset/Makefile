.PATH:${.CURDIR}/../../lib

PROG = idset_test
SRCS = error.c sha1.c object_idset.c inflate.c object_parse.c idset_test.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib
LDADD = -lutil -lz

NOMAN = yes

.include <bsd.regress.mk>
