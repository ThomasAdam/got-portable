sbin_PROGRAMS = gotd

include $(top_builddir)/Makefile.common

gotd_SOURCES = gotd.c \
	auth.c \
	imsg.c \
	listen.c \
	log.c \
	parse.y \
	privsep_stub.c \
	repo_imsg.c \
	repo_read.c \
	repo_write.c \
	session.c \
	$(top_srcdir)/lib/bloom.c \
	$(top_srcdir)/lib/buf.c \
	$(top_srcdir)/lib/date.c \
	$(top_srcdir)/lib/deflate.c \
	$(top_srcdir)/lib/delta.c \
	$(top_srcdir)/lib/delta_cache.c \
	$(top_srcdir)/lib/deltify.c \
	$(top_srcdir)/lib/error.c \
	$(top_srcdir)/lib/gitconfig.c \
	$(top_srcdir)/lib/gotconfig.c \
	$(top_srcdir)/lib/inflate.c \
	$(top_srcdir)/lib/lockfile.c \
	$(top_srcdir)/lib/murmurhash2.c \
	$(top_srcdir)/lib/object.c \
	$(top_srcdir)/lib/object_cache.c \
	$(top_srcdir)/lib/object_create.c \
	$(top_srcdir)/lib/object_idset.c \
	$(top_srcdir)/lib/object_open_io.c \
	$(top_srcdir)/lib/object_parse.c \
	$(top_srcdir)/lib/opentemp.c \
	$(top_srcdir)/lib/pack.c \
	$(top_srcdir)/lib/pack_create.c \
	$(top_srcdir)/lib/pack_create_io.c \
	$(top_srcdir)/lib/pack_index.c \
	$(top_srcdir)/lib/path.c \
	$(top_srcdir)/lib/pollfd.c \
	$(top_srcdir)/lib/ratelimit.c \
	$(top_srcdir)/lib/read_gitconfig.c \
	$(top_srcdir)/lib/read_gotconfig.c \
	$(top_srcdir)/lib/reference.c \
	$(top_srcdir)/lib/reference_parse.c \
	$(top_srcdir)/lib/repository.c \
	$(top_srcdir)/lib/sha1.c \
	$(top_srcdir)/lib/sigs.c
       
gotd_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a
EXTRA_DIST = gotd.8 gotd.conf.5 *.h

man5_MANS = gotd.conf.5
man8_MANS = gotd.8

LDADD = -L$(top_builddir)/compat -lopenbsd-compat -lm
if HOST_FREEBSD
LDADD += -lmd
endif
