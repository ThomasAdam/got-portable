bin_PROGRAMS = gotsh

include $(top_builddir)/Makefile.common

AM_CPPFLAGS += -I$(top_builddir)/gotd

gotsh_SOURCES = gotsh.c \
	$(top_srcdir)/gotd/imsg.c \
	$(top_srcdir)/lib/error.c \
	$(top_srcdir)/lib/gitproto.c \
	$(top_srcdir)/lib/path.c \
	$(top_srcdir)/lib/pkt.c \
	$(top_srcdir)/lib/pollfd.c \
	$(top_srcdir)/lib/reference_parse.c \
	$(top_srcdir)/lib/serve.c \
	$(top_srcdir)/lib/sha1.c
       
gotsh_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a
EXTRA_DIST = gotsh.1

man1_MANS = gotsh.1

LDADD = -L$(top_builddir)/compat -L$(top_builddir)/gotd -lopenbsd-compat -lm
if HOST_FREEBSD
LDADD += -lmd
endif

# Disable for now (per upstream)...
#
#install-exec-hook:
#	ln -sf $(prefix)/bin/gotsh $(prefix)/bin/git-receive-pack
#	ln -sf $(prefix)/bin/gotsh $(prefix)/bin/git-upload-pack
