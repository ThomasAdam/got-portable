bin_PROGRAMS = gotadmin

include $(top_builddir)/Makefile.common

gotadmin_SOURCES = gotadmin.c \
       $(top_srcdir)/lib/deflate.c \
       $(top_srcdir)/lib/delta.c \
       $(top_srcdir)/lib/delta_cache.c \
       $(top_srcdir)/lib/deltify.c \
       $(top_srcdir)/lib/error.c \
       $(top_srcdir)/lib/gotconfig.c \
       $(top_srcdir)/lib/inflate.c \
       $(top_srcdir)/lib/lockfile.c \
       $(top_srcdir)/lib/object.c \
       $(top_srcdir)/lib/object_cache.c \
       $(top_srcdir)/lib/object_create.c \
       $(top_srcdir)/lib/object_idset.c \
       $(top_srcdir)/lib/object_parse.c \
       $(top_srcdir)/lib/opentemp.c \
       $(top_srcdir)/lib/pack.c \
       $(top_srcdir)/lib/pack_create.c \
       $(top_srcdir)/lib/path.c \
       $(top_srcdir)/lib/privsep.c \
       $(top_srcdir)/lib/reference.c \
       $(top_srcdir)/lib/repository.c \
       $(top_srcdir)/lib/repository_admin.c \
       $(top_srcdir)/lib/sha1.c

gotadmin_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a

man1_MANS = gotadmin.1

LDADD = -L$(top_builddir)/compat -lopenbsd-compat
if HOST_FREEBSD
LDADD += -lmd
endif
