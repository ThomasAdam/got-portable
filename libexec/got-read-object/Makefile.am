libexec_PROGRAMS = got-read-object

include $(top_builddir)/Makefile.common

got_read_object_SOURCES = got-read-object.c \
	$(top_srcdir)/lib/error.c \
	$(top_srcdir)/lib/inflate.c \
	$(top_srcdir)/lib/object_parse.c \
	$(top_srcdir)/lib/path.c \
	$(top_srcdir)/lib/pollfd.c \
	$(top_srcdir)/lib/privsep.c \
	$(top_srcdir)/lib/sha1.c

got_read_object_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a

LDADD = -L$(top_builddir)/compat -lopenbsd-compat
if HOST_FREEBSD
LDADD += -lmd
endif
