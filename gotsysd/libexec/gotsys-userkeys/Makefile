.PATH: ${.CURDIR}/../../../gotsys ${.CURDIR}/../.. ${.CURDIR}/../../../lib

.include "../../../got-version.mk"

PROG=		gotsys-userkeys
SRCS=		gotsys-userkeys.c error.c hash.c pollfd.c path.c opentemp.c \
		imsg.c gotsys_conf.c gotsys_imsg.c

CPPFLAGS = -I${.CURDIR}/../../../include -I${.CURDIR}/../../../lib \
	-I${.CURDIR}/../../../gotsys -I${.CURDIR}/../../ -I${.CURDIR}
YFLAGS =

.if defined(PROFILE)
LDADD = -lutil_p -levent_p
.else
LDADD = -lutil -levent
.endif

DPADD = ${LIBUTIL} ${LIBEVENT}


.include <bsd.prog.mk>
