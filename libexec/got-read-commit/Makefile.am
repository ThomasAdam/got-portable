bin_PROGRAMS = got-read-commit
got_read_commit_SOURCES = got-read-commit.c \
	$(top_srcdir)/lib/error.c \
	$(top_srcdir)/lib/inflate.c \
	$(top_srcdir)/lib/object_parse.c \
	$(top_srcdir)/lib/path.c \
	$(top_srcdir)/lib/privsep.c \
	$(top_srcdir)/lib/sha1.c

got_read_commit_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a

AM_CPPFLAGS += -DGOT_VERSION='"@VERSION@"' \
	-DGOT_VERSION_NUMBER='"@VERSION@"' \
	-DGOT_LIBEXECDIR="${bindir}" \
	-I$(top_srcdir) \
	-I$(top_srcdir)/compat \
	-I$(top_srcdir)/lib \
	-I$(top_srcdir)/include \
	-I.

LDADD = -L$(top_builddir)/compat -lopenbsd-compat
