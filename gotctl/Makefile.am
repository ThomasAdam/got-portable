bin_PROGRAMS = gotctl

include $(top_builddir)/Makefile.common

AM_CPPFLAGS += -I$(top_builddir)/gotd

gotctl_SOURCES = gotctl.c \
	$(top_srcdir)/gotd/imsg.c \
	$(top_srcdir)/lib/error.c \
	$(top_srcdir)/lib/gitproto.c \
	$(top_srcdir)/lib/path.c \
	$(top_srcdir)/lib/pkt.c \
	$(top_srcdir)/lib/pollfd.c \
	$(top_srcdir)/lib/reference_parse.c \
	$(top_srcdir)/lib/serve.c \
	$(top_srcdir)/lib/sha1.c
       
gotctl_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a
EXTRA_DIST = gotctl.8

man8_MANS = gotctl.8

LDADD = -L$(top_builddir)/compat -L$(top_builddir)/gotd -lopenbsd-compat -lm
if HOST_FREEBSD
LDADD += -lmd
endif
