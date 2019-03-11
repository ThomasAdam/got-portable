.PATH:${.CURDIR}/../../lib

PROG = idset_test
SRCS = error.c object.c privsep.c sha1.c pack.c inflate.c path.c opentemp.c \
	delta.c repository.c reference.c worktree.c fileindex.c object_cache.c \
	object_idset.c object_parse.c idset_test.c \
	buf.c worklist.c rcsutil.c diff.c diffreg.c diff3.c lockfile.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib
LDADD = -lutil -lz

NOMAN = yes

.include <bsd.regress.mk>
