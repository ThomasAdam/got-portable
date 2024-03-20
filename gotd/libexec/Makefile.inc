.include "../../Makefile.inc"

realinstall:
	${INSTALL} ${INSTALL_COPY} -o ${BINOWN} -g ${BINGRP} \
	-m ${BINMODE} ${PROG} ${LIBEXECDIR}/${PROG}

NOMAN = Yes
