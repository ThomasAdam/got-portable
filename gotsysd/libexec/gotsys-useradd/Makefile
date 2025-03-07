.PATH: ${.CURDIR}/../../../gotsys ${.CURDIR}/../.. ${.CURDIR}/../../../lib

.include "../../../got-version.mk"

PROG=		gotsys-useradd
SRCS=		gotsys-useradd.c pwd_mkdb.c error.c hash.c pollfd.c path.c \
		imsg.c gotsys_conf.c gotsys_imsg.c opentemp.c gotsys_uidset.c

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
