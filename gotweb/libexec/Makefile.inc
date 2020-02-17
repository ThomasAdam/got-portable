.include "../Makefile.inc"

realinstall:
	if [ ! -d ${DESTDIR}${CHROOT_DIR}${LIBEXECDIR}/. ]; then \
		${INSTALL} -d -o root -g daemon -m 755 \
		    ${DESTDIR}${CHROOT_DIR}${LIBEXECDIR}; \
	fi
	${INSTALL} ${INSTALL_COPY} -o root -g daemon -m 755 ${PROG} \
	    ${DESTDIR}${CHROOT_DIR}${LIBEXECDIR}/${PROG}

NOMAN = Yes
