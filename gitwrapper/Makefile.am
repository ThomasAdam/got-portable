bin_PROGRAMS = gitwrapper

include $(top_builddir)/Makefile.common

AM_CPPFLAGS += -I$(top_builddir)/gotd

CLEANFILES = parse.h

gitwrapper_SOURCES = gitwrapper.c \
		  $(top_srcdir)/gotd/auth.c \
		  $(top_srcdir)/gotd/imsg.c \
		  $(top_srcdir)/gotd/listen.c \
		  $(top_srcdir)/gotd/log.c \
		  $(top_srcdir)/gotd/parse.y \
		  $(top_srcdir)/gotd/privsep_stub.c \
		  $(top_srcdir)/lib/bloom.c \
		  $(top_srcdir)/lib/buf.c \
		  $(top_srcdir)/lib/date.c \
		  $(top_srcdir)/lib/deflate.c \
		  $(top_srcdir)/lib/delta.c \
		  $(top_srcdir)/lib/delta_cache.c \
		  $(top_srcdir)/lib/dial.c \
		  $(top_srcdir)/lib/error.c \
		  $(top_srcdir)/lib/gitconfig.c \
		  $(top_srcdir)/lib/gitproto.c \
		  $(top_srcdir)/lib/gotconfig.c \
		  $(top_srcdir)/lib/hash.c \
		  $(top_srcdir)/lib/inflate.c \
		  $(top_srcdir)/lib/lockfile.c \
		  $(top_srcdir)/lib/murmurhash2.c \
		  $(top_srcdir)/lib/object.c \
		  $(top_srcdir)/lib/object_cache.c \
		  $(top_srcdir)/lib/object_create.c \
		  $(top_srcdir)/lib/object_idset.c \
		  $(top_srcdir)/lib/object_open_io.c \
		  $(top_srcdir)/lib/object_parse.c \
		  $(top_srcdir)/lib/object_qid.c \
		  $(top_srcdir)/lib/opentemp.c \
		  $(top_srcdir)/lib/pack.c \
		  $(top_srcdir)/lib/path.c \
		  $(top_srcdir)/lib/pkt.c \
		  $(top_srcdir)/lib/pollfd.c \
		  $(top_srcdir)/lib/read_gitconfig.c \
		  $(top_srcdir)/lib/read_gotconfig.c \
		  $(top_srcdir)/lib/reference.c \
		  $(top_srcdir)/lib/reference_parse.c \
		  $(top_srcdir)/lib/repository.c \
		  $(top_srcdir)/lib/serve.c \
		  $(top_srcdir)/lib/sigs.c

gitwrapper_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a
EXTRA_DIST = gitwrapper.1

man1_MANS = gitwrapper.1

LDADD = -L$(top_builddir)/compat -lopenbsd-compat -lm
LDADD += $(libbsd_LIBS) \
	 $(libevent_LIBS) \
	 $(zlib_LIBS) \
	 $(libuuid_LIBS) \
	 $(libutil_LIBS)
if HOST_FREEBSD
LDADD += -lmd
endif

AM_CPPFLAGS += $(libbsd_CFLAGS) $(libevent_CFLAGS) $(zlib_CFLAGS) \
	       $(libuuid_CFLAGS)
