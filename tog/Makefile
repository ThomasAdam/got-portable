.PATH:${.CURDIR}/../lib

PROG=		tog
SRCS=		tog.c error.c

CPPFLAGS = -I${.CURDIR}/../include -I${.CURDIR}/../lib
LDADD = -lpanel -lcurses -lutil -lz
DPADD = ${LIBZ} ${LIBUTIL}
.if defined(PROFILE)
CC = gcc
CPPFLAGS += -DPROFILE
DEBUG = -O0 -pg
.else
DEBUG = -O0 -g
.endif
CFLAGS += -Werror -Wall -Wstrict-prototypes -Wunused-variable

# For now, default to installing binary in ~/bin
GROUP!=id -g -n
install:
	${INSTALL} ${INSTALL_COPY} -o ${USER} -g ${GROUP} \
	-m ${BINMODE} ${PROG} ${HOME}/bin/${PROG}

# Don't install man pages yet
NOMAN = Yes

.include <bsd.prog.mk>
