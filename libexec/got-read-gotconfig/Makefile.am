libexec_PROGRAMS = got-read-gotconfig

include $(top_builddir)/Makefile.common

got_read_gotconfig_SOURCES = \
	$(top_srcdir)/lib/error.c \
	$(top_srcdir)/lib/hash.c \
	$(top_srcdir)/lib/inflate.c \
	$(top_srcdir)/lib/object_parse.c \
	$(top_srcdir)/lib/path.c \
	$(top_srcdir)/lib/pollfd.c \
	$(top_srcdir)/lib/privsep.c \
	got-read-gotconfig.c \
	gotconfig.h \
	parse.y

got_read_gotconfig_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a

LDADD = -L$(top_builddir)/compat -lopenbsd-compat
if HOST_FREEBSD
LDADD += -lmd
endif
