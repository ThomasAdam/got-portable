.PATH:${.CURDIR}/../lib

SUBDIR = ../libexec

.include "../got-version.mk"

PROG =		gotweb
SRCS =		gotweb.c parse.y blame.c commit_graph.c delta.c diff.c \
		diffreg.c error.c fileindex.c object.c object_cache.c \
		object_idset.c object_parse.c opentemp.c path.c pack.c \
		privsep.c reference.c repository.c sha1.c worktree.c \
		inflate.c buf.c rcsutil.c diff3.c lockfile.c \
		deflate.c object_create.c delta_cache.c
MAN =		${PROG}.conf.5

CPPFLAGS +=	-I${.CURDIR}/../include -I${.CURDIR}/../lib -I${.CURDIR} \
		-I${PREFIX}/include

LDADD +=	-L${PREFIX}/lib -static -lkcgihtml -lkcgi -lz -lutil

.if ${GOT_RELEASE} != "Yes"
NOMAN = Yes
.endif

realinstall:
	if [ ! -d ${CGI_DIR}/. ]; then \
		${INSTALL} -d -o root -g daemon -m 755 ${CGI_DIR}; \
	fi
	if [ ! -d ${PUB_REPOS_DIR}/. ]; then \
		${INSTALL} -d -o root -g daemon -m 755 ${PUB_REPOS_DIR}; \
	fi
	${INSTALL} -c -o ${WWWUSR} -g ${WWWGRP} -m 0755 ${PROG} \
	    ${CGI_DIR}/${PROG}
	if [ ! -d ${TMPL_DIR}/. ]; then \
		${INSTALL} -d -o root -g daemon -m 755 ${TMPL_DIR}; \
	fi
	${INSTALL} -c -o ${WWWUSR} -g ${WWWGRP} -m 0755 \
	    ${.CURDIR}/files/cgi-bin/gw_tmpl/* ${TMPL_DIR}
	if [ ! -d ${HTTPD_DIR}/. ]; then \
		${INSTALL} -d -o root -g daemon -m 755 ${HTTPD_DIR}; \
	fi
	if [ ! -d ${TMP_DIR}/. ]; then \
		${INSTALL} -d -o ${WWWUSR} -g ${WWWGRP} -m 755 ${TMP_DIR}; \
	fi
	if [ ! -d ${PROG_DIR}/. ]; then \
		${INSTALL} -d -o root -g daemon -m 755 ${PROG_DIR}; \
	fi
	${INSTALL} -c -o ${WWWUSR} -g ${WWWGRP} -m 0755 \
	    ${.CURDIR}/files/htdocs/${PROG}/* ${PROG_DIR}

.include <bsd.prog.mk>
