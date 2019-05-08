.PATH:${.CURDIR}/../../lib

PROG = repository_test
SRCS = path.c repository.c error.c reference.c object.c object_cache.c \
	object_idset.c object_parse.c opentemp.c sha1.c diff.c diffreg.c \
	pack.c privsep.c delta.c fileindex.c worktree.c inflate.c \
	buf.c worklist.c rcsutil.c diff3.c lockfile.c deflate.c \
	object_create.c repository_test.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib \
	-DGOT_LIBEXECDIR=${GOT_LIBEXECDIR}
LDADD = -lutil -lz

NOMAN = yes

.include <bsd.regress.mk>
