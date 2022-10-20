libexec_PROGRAMS = got-index-pack

include $(top_builddir)/Makefile.common

got_index_pack_SOURCES = got-index-pack.c \
	$(top_srcdir)/lib/error.c \
	$(top_srcdir)/lib/inflate.c \
	$(top_srcdir)/lib/object_parse.c \
	$(top_srcdir)/lib/object_idset.c \
	$(top_srcdir)/lib/delta_cache.c \
	$(top_srcdir)/lib/delta.c \
	$(top_srcdir)/lib/pack.c \
	$(top_srcdir)/lib/pack_index.c \
	$(top_srcdir)/lib/path.c \
	$(top_srcdir)/lib/privsep.c \
	$(top_srcdir)/lib/sha1.c \
	$(top_srcdir)/lib/ratelimit.c

got_index_pack_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a

LDADD = -L$(top_builddir)/compat -lopenbsd-compat
if HOST_FREEBSD
LDADD += -lmd
endif
