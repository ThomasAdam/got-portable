libexec_PROGRAMS = got-notify-http

include $(top_builddir)/Makefile.common

got_notify_http_SOURCES = got-notify-http.c \
	$(top_srcdir)/gotd/log.c \
	$(top_srcdir)/lib/bufio.c \
	$(top_srcdir)/lib/error.c \
	$(top_srcdir)/lib/hash.c \
	$(top_srcdir)/lib/opentemp.c \
	$(top_srcdir)/lib/pollfd.c

got_notify_http_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a

LDADD = -L$(top_builddir)/compat -lopenbsd-compat
LDADD += $(zlib_LIBS) $(libbsd_LIBS) $(libutil_LIBS) $(libmd_LIBS) $(libtls_LIBS)
if HOST_FREEBSD
LDADD += -lmd
endif

AM_CPPFLAGS += $(zlib_CFLAGS) $(libbsd_CFLAGS) $(libmd_CFLAGS) $(libtls_CFLAGS)
