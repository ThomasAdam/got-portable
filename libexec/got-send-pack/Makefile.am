libexec_PROGRAMS = got-send-pack

include $(top_builddir)/Makefile.common

got_send_pack_SOURCES = \
	got-send-pack.c \
	$(top_srcdir)/lib/error.c \
	$(top_srcdir)/lib/gitproto.c \
	$(top_srcdir)/lib/hash.c \
	$(top_srcdir)/lib/inflate.c \
	$(top_srcdir)/lib/object_parse.c \
	$(top_srcdir)/lib/path.c \
	$(top_srcdir)/lib/pkt.c \
	$(top_srcdir)/lib/pollfd.c \
	$(top_srcdir)/lib/privsep.c \
	$(top_srcdir)/lib/ratelimit.c \
	$(top_srcdir)/lib/reference_parse.c

got_send_pack_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a

LDADD = -L$(top_builddir)/compat -lopenbsd-compat
if HOST_FREEBSD
LDADD += -lmd
endif
