noinst_LIBRARIES = libopenbsd-compat.a

include $(top_builddir)/Makefile.common

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
	strndup.c \
	strnlen.c \
	strsep.c \
	strtonum.c \
	imsg.h \
	queue.h \
	tree.h

# For MacOS, don't build the compat versions of strl{cat,cpy}, but do for all
# other systems.
if !HOST_DARWIN
libopenbsd_compat_a_SOURCES += strlcat.c strlcpy.c
endif

if HOST_DARWIN
libopenbsd_compat_a_SOURCES += uuid.c bsd-poll.c bsd-poll.h
endif

if HOST_NETBSD
libopenbsd_compat_a_SOURCES += bsd-poll.c bsd-poll.h
endif

if HOST_LINUX
libopenbsd_compat_a_SOURCES += uuid.c
endif

if HAVE_LINUX_LANDLOCK
libopenbsd_compat_a_SOURCES += landlock.c
endif

if !HAVE_SIPHASH
libopenbsd_compat_a_SOURCES += siphash.c siphash.h
endif

if !HAVE_SETPROCTITLE
libopenbsd_compat_a_SOURCES += setproctitle.c
endif

EXTRA_DIST = \
	$(top_srcdir)/include/got_compat.h \
	imsg.h \
	queue.h \
	tree.h \
	bsd-poll.h
