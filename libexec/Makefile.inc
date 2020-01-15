.include "../Makefile.inc"

.if "${MAKEWEB}" == "Yes"
realinstall:
	if [ ! -d ${CHROOT_DIR}${LIBEXECDIR}/. ]; then \
		${INSTALL} -d -o root -g daemon -m 755 \
		    ${CHROOT_DIR}${LIBEXECDIR}; \
	fi
	${INSTALL} ${INSTALL_COPY} -o root -g daemon -m 755 ${PROG} \
	    ${CHROOT_DIR}${LIBEXECDIR}/${PROG}
.else
realinstall:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} \
	-m ${BINMODE} ${PROG} ${LIBEXECDIR}/${PROG}
.endif
NOMAN = Yes
