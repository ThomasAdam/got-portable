.PATH:${.CURDIR}/../../lib

PROG=		got-read-commit
SRCS=		got-read-commit.c delta.c error.c inflate.c object_parse.c \
		privsep.c sha1.c

CPPFLAGS = -I${.CURDIR}/../../include -I${.CURDIR}/../../lib
LDADD = -lutil -lz
DPADD = ${LIBZ} ${LIBUTIL}
.if defined(PROFILE)
CC = gcc
CPPFLAGS += -DPROFILE
DEBUG = -O0 -pg
.else
DEBUG = -O0 -g
.endif
CFLAGS += -Werror -Wall -Wstrict-prototypes -Wunused-variable
#CFLAGS += -DGOT_PACK_NO_MMAP
#CFLAGS += -DGOT_NO_OBJ_CACHE

# For now, default to installing binary in ~/bin
LIBEXECDIR = ${HOME}/bin
GROUP!=id -g -n
install:
	${INSTALL} ${INSTALL_COPY} -o ${USER} -g ${GROUP} \
	-m ${BINMODE} ${PROG} ${LIBEXECDIR}/${PROG}

# Don't install man pages yet
NOMAN = Yes

.include <bsd.prog.mk>
