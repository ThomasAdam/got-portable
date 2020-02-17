.PATH:${.CURDIR}/../lib

SUBDIR = libexec

.include "../got-version.mk"
.include "Makefile.inc"

PROG =		gotweb
SRCS =		gotweb.c parse.y blame.c commit_graph.c delta.c diff.c \
		diffreg.c error.c fileindex.c object.c object_cache.c \
		object_idset.c object_parse.c opentemp.c path.c pack.c \
		privsep.c reference.c repository.c sha1.c worktree.c \
		inflate.c buf.c rcsutil.c diff3.c lockfile.c \
		deflate.c object_create.c delta_cache.c
MAN =		${PROG}.conf.5 ${PROG}.8

CPPFLAGS +=	-I${.CURDIR}/../include -I${.CURDIR}/../lib -I${.CURDIR} \
		-I${KCGIBASE}/include
LDADD +=	-L${KCGIBASE}/lib -lkcgihtml -lkcgi -lz
LDSTATIC =	${STATIC}

.if ${GOT_RELEASE} != "Yes"
NOMAN = Yes
.endif

realinstall:
	if [ ! -d ${DESTDIR}${CGI_DIR}/. ]; then \
		${INSTALL} -d -o root -g daemon -m 755 ${DESTDIR}${CGI_DIR}; \
	fi
	if [ ! -d ${DESTDIR}${PUB_REPOS_DIR}/. ]; then \
		${INSTALL} -d -o root -g daemon -m 755 ${DESTDIR}${PUB_REPOS_DIR}; \
	fi
	${INSTALL} -c -o ${WWWUSR} -g ${WWWGRP} -m 0755 ${PROG} \
	    ${DESTDIR}${CGI_DIR}/${PROG}
	if [ ! -d ${DESTDIR}${TMPL_DIR}/. ]; then \
		${INSTALL} -d -o root -g daemon -m 755 ${DESTDIR}${TMPL_DIR}; \
	fi
	${INSTALL} -c -o ${WWWUSR} -g ${WWWGRP} -m 0755 \
	    ${.CURDIR}/files/cgi-bin/gw_tmpl/* ${DESTDIR}${TMPL_DIR}
	if [ ! -d ${DESTDIR}${HTTPD_DIR}/. ]; then \
		${INSTALL} -d -o root -g daemon -m 755 ${DESTDIR}${HTTPD_DIR}; \
	fi
	if [ ! -d ${DESTDIR}${TMP_DIR}/. ]; then \
		${INSTALL} -d -o ${WWWUSR} -g ${WWWGRP} -m 755 ${DESTDIR}${TMP_DIR}; \
	fi
	if [ ! -d ${DESTDIR}${PROG_DIR}/. ]; then \
		${INSTALL} -d -o root -g daemon -m 755 ${DESTDIR}${PROG_DIR}; \
	fi
	${INSTALL} -c -o ${WWWUSR} -g ${WWWGRP} -m 0755 \
	    ${.CURDIR}/files/htdocs/${PROG}/* ${DESTDIR}${PROG_DIR}

.include <bsd.prog.mk>
