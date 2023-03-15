noinst_LIBRARIES = libopenbsd-compat.a

include $(top_builddir)/Makefile.common

LDADD = $(libbsd_LIBS)
AM_CPPFLAGS += $(libbsd_CFLAGS)

libopenbsd_compat_a_SOURCES =  \
	asprintf.c \
	fmt_scaled.c \
	freezero.c \
	getdtablecount.c \
	getprogname.c \
	merge.c \
	reallocarray.c \
	recallocarray.c \
	strndup.c \
	strnlen.c \
	strsep.c \
	strtonum.c \
	imsg.h \
	tree.h

# For MacOS, don't build the compat versions of strl{cat,cpy}, but do for all
# other systems.
if !HOST_DARWIN
libopenbsd_compat_a_SOURCES += strlcat.c strlcpy.c
endif

if HOST_DARWIN
libopenbsd_compat_a_SOURCES += uuid.c bsd-poll.c bsd-poll.h
endif

if !HAVE_GETOPT
libopenbsd_compat_a_SOURCES += getopt.c
endif

if !HAVE_B64
libopenbsd_compat_a_SOURCES += base64.c
LDADD += $(libresolv_LIBS)
endif

if !HAVE_CLOSEFROM
libopenbsd_compat_a_SOURCES += closefrom.c
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

if !HAVE_IMSG
libopenbsd_compat_a_SOURCES += imsg-buffer.c imsg.c
endif

if !HOST_DARWIN
# Fake an assigment here.  It does nothing, but you cannot have consecutive
# nested if statements in Makefiles, so we have to do something here, even if
# it's a dummy assignment.
NOTING=something
if !HAVE_SHA2
libopenbsd_compat_a_SOURCES += sha2.c sha2.h
endif
endif

EXTRA_DIST = \
	$(top_srcdir)/include/got_compat.h \
	imsg.h \
	tree.h \
	bsd-poll.h
