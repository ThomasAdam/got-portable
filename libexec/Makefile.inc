.include "../Makefile.inc"

.if ${MAKEWEB} == "Yes"
realinstall:
	if [ ! -d ${LIBEXEC_DIR}/. ]; then \
		${INSTALL} -d -o root -g daemon -m 755 ${LIBEXEC_DIR}; \
	fi
	${INSTALL} ${INSTALL_COPY} -o root -g daemon -m 755 ${PROG} \
	${LIBEXEC_DIR}/${PROG}
.else
realinstall:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} \
	-m ${BINMODE} ${PROG} ${LIBEXECDIR}/${PROG}
.endif
NOMAN = Yes
