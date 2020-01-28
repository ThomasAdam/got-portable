CPPFLAGS += -DGOT_LIBEXECDIR=${LIBEXECDIR} -DGOT_VERSION=${GOT_VERSION}
CFLAGS += -Werror -Wall -Wstrict-prototypes -Wunused-variable
#CFLAGS += -DGOT_PACK_NO_MMAP
#CFLAGS += -DGOT_NO_OBJ_CACHE
#CFLAGS += -DGOT_OBJ_CACHE_DEBUG

.if "${GOT_RELEASE}" == "Yes"
PREFIX ?= /usr/local
BINDIR ?= ${PREFIX}/bin
LIBEXECDIR ?= ${PREFIX}/libexec
MANDIR ?= ${PREFIX}/man/man
.else
PREFIX ?= ${HOME}
BINDIR ?= ${PREFIX}/bin
LIBEXECDIR ?= ${BINDIR}

BINOWN ?= ${USER}
.if !defined(BINGRP)
BINGRP != id -g -n
.endif

.if defined(PROFILE)
CPPFLAGS += -DPROFILE
DEBUG = -O0 -pg -g -static
.else
DEBUG = -O0 -g
.endif

.endif

.if "${MAKEWEB}" == "Yes"
LDADD =		-L${PREFIX}/lib -static -lkcgihtml -lkcgi -lz -lutil
PREFIX =	/usr/local
CHROOT_DIR =	/var/www
GOTWEB_DIR =	/cgi-bin/gotweb
LIBEXECDIR =	${GOTWEB_DIR}/libexec
LIBEXEC_DIR =	${CHROOT_DIR}${LIBEXECDIR}
ETC_DIR =	${CHROOT_DIR}/etc
HTTPD_DIR =	${CHROOT_DIR}/htdocs
TMP_DIR =	${CHROOT_DIR}/tmp
PROG_DIR =	${HTTPD_DIR}/${PROG}
CGI_DIR =	${CHROOT_DIR}${GOTWEB_DIR}
TMPL_DIR =	${CGI_DIR}/gw_tmpl
PUB_REPOS_DIR =	${CHROOT_DIR}/got/public
WWWUSR ?=	www
WWWGRP ?=	www
.endif
