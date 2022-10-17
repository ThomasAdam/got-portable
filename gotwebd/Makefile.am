sbin_PROGRAMS = gotwebd

include $(top_builddir)/Makefile.common

gotwebd_SOURCES = config.c \
		  $(top_srcdir)/lib/blame.c \
		  $(top_srcdir)/lib/bloom.c \
		  $(top_srcdir)/lib/buf.c \
		  $(top_srcdir)/lib/commit_graph.c \
		  $(top_srcdir)/lib/date.c \
		  $(top_srcdir)/lib/deflate.c \
		  $(top_srcdir)/lib/delta.c \
		  $(top_srcdir)/lib/delta_cache.c \
		  $(top_srcdir)/lib/diff.c \
		  $(top_srcdir)/lib/diff3.c \
		  $(top_srcdir)/lib/diff_atomize_text.c \
		  $(top_srcdir)/lib/diff_main.c \
		  $(top_srcdir)/lib/diff_myers.c \
		  $(top_srcdir)/lib/diff_output.c \
		  $(top_srcdir)/lib/diff_output_edscript.c \
		  $(top_srcdir)/lib/diff_output_plain.c \
		  $(top_srcdir)/lib/diff_output_unidiff.c \
		  $(top_srcdir)/lib/diff_patience.c \
		  $(top_srcdir)/lib/diffreg.c \
		  $(top_srcdir)/lib/error.c \
		  $(top_srcdir)/lib/fileindex.c \
		  $(top_srcdir)/lib/gotconfig.c \
		  $(top_srcdir)/lib/inflate.c \
		  $(top_srcdir)/lib/lockfile.c \
		  $(top_srcdir)/lib/murmurhash2.c \
		  $(top_srcdir)/lib/object.c \
		  $(top_srcdir)/lib/object_cache.c \
		  $(top_srcdir)/lib/object_create.c \
		  $(top_srcdir)/lib/object_idset.c \
		  $(top_srcdir)/lib/object_open_privsep.c \
		  $(top_srcdir)/lib/object_parse.c \
		  $(top_srcdir)/lib/opentemp.c \
		  $(top_srcdir)/lib/pack.c \
		  $(top_srcdir)/lib/patch.c \
		  $(top_srcdir)/lib/path.c \
		  $(top_srcdir)/lib/privsep.c \
		  $(top_srcdir)/lib/rcsutil.c \
		  $(top_srcdir)/lib/read_gitconfig_privsep.c \
		  $(top_srcdir)/lib/read_gotconfig_privsep.c \
		  $(top_srcdir)/lib/reference.c \
		  $(top_srcdir)/lib/repository.c \
		  $(top_srcdir)/lib/sha1.c \
		  $(top_srcdir)/lib/sigs.c \
		  $(top_srcdir)/lib/utf8.c \
		  $(top_srcdir)/lib/worktree.c \
		  $(top_srcdir)/lib/worktree_open.c \
		  fcgi.c \
		  got_operations.c \
		  gotweb.c \
		  gotwebd.c \
		  log.c \
		  parse.y \
		  proc.c \
		  sockets.c
if HOST_LINUX
nodist_gotwebd_SOURCES = $(top_srcdir)/compat/sockaddr-@PLATFORM@.c
else
nodist_gotwebd_SOURCES = $(top_srcdir)/lib/sockaddr.c
endif

gotwebd_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a
EXTRA_DIST = $(top_srcdir)/gotwebd/*.h \
	     gotwebd.8 gotwebd.conf.5

man5_MANS = gotwebd.conf.5
man8_MANS = gotwebd.8

LDADD = -L$(top_builddir)/compat -lopenbsd-compat -lm
if HOST_FREEBSD
LDADD += -lmd
endif

#realinstall:
#	if [ ! -d ${DESTDIR}${PUB_REPOS_DIR}/. ]; then \
#		${INSTALL} -d -o root -g daemon -m 755 ${DESTDIR}${PUB_REPOS_DIR}; \
#	fi
#	${INSTALL} -c -o root -g daemon -m 0755 ${PROG} ${BINDIR}/${PROG}
#	if [ ! -d ${DESTDIR}${HTTPD_DIR}/. ]; then \
#		${INSTALL} -d -o root -g daemon -m 755 ${DESTDIR}${HTTPD_DIR}; \
#	fi
#	if [ ! -d ${DESTDIR}${PROG_DIR}/. ]; then \
#		${INSTALL} -d -o root -g daemon -m 755 ${DESTDIR}${PROG_DIR}; \
#	fi
#	${INSTALL} -c -o ${WWWUSR} -g ${WWWGRP} -m 0755 \
#	    ${.CURDIR}/files/htdocs/${PROG}/* ${DESTDIR}${PROG_DIR}
#
#.include <bsd.prog.mk>
