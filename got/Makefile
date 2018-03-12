
PROG=		got
SRCS=		got.c

CFLAGS+=	-W -Wall -Wstrict-prototypes -Wunused-variable

# libgit2
CFLAGS+=	-I/usr/local/include
LDADD+=		-L/usr/local/lib -lgit2

.include <bsd.prog.mk>
