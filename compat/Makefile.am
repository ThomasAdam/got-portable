noinst_LIBRARIES = libopenbsd-compat.a

AM_CPPFLAGS += -DGOT_VERSION='"@VERSION@"' \
	-DGOT_VERSION_NUMBER='"@VERSION@"' \
	-DGOT_LIBEXECDIR="${bindir}" \
	-I$(top_srcdir) \
	-I$(top_srcdir)/compat \
	-I$(top_srcdir)/lib \
	-I$(top_srcdir)/include \
	-I.

libopenbsd_compat_a_SOURCES =  \
	asprintf.c \
	base64.c \
	closefrom.c \
	fmt_scaled.c \
	freezero.c \
	getdtablecount.c \
	getopt.c \
	getprogname.c \
	imsg-buffer.c \
	imsg.c \
	merge.c \
	reallocarray.c \
	recallocarray.c \
	strlcat.c \
	strlcpy.c \
	strndup.c \
	strnlen.c \
	strsep.c \
	strtonum.c \
	imsg.h \
	queue.h \
	tree.h
if HOST_FREEBSD
else
libopenbsd_compat_a_SOURCES += uuid.c
endif

EXTRA_DIST = \
	$(top_srcdir)/include/got_compat.h \
	imsg.h \
	queue.h \
	tree.h
