.PATH:${.CURDIR}/../../lib

PROG = worktree_test
SRCS = worktree.c repository.c object.c object_cache.c object_idset.c \
	object_parse.c opentemp.c path.c error.c reference.c sha1.c pack.c \
	privsep.c delta.c inflate.c fileindex.c \
	buf.c worklist.c rcsutil.c diff.c diffreg.c diff3.c lockfile.c \
	deflate.c object_create.c worktree_test.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib \
	-DGOT_LIBEXECDIR=${GOT_LIBEXECDIR}
LDADD = -lutil -lz

NOMAN = yes

.include <bsd.regress.mk>
