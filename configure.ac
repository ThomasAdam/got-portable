# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([got-portable], [0.75], [thomas@xteddy.org])
AC_CONFIG_AUX_DIR(etc)
AC_CONFIG_SRCDIR([lib/rcsutil.h])
AM_INIT_AUTOMAKE([foreign subdir-objects])

GOT_RELEASE=No

AC_DEFINE_UNQUOTED(VERSION, "$VERSION")
AC_SUBST(VERSION)
AC_SUBST(GOT_RELEASE)

AC_CANONICAL_HOST

# When CFLAGS isn't set at this stage and gcc is detected by the macro below,
# autoconf will automatically use CFLAGS="-O2 -g". Prevent that by using an
# empty default.
: ${CFLAGS=""}

# Save user CPPFLAGS, CFLAGS and LDFLAGS. We need to change them because
# AC_CHECK_HEADER doesn't give us any other way to update the include
# paths. But for Makefile.am we want to use AM_CPPFLAGS and friends.
SAVED_CFLAGS="$CFLAGS"
SAVED_CPPFLAGS="$CPPFLAGS"
SAVED_LDFLAGS="$LDFLAGS"

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_YACC
AC_PROG_RANLIB
PKG_PROG_PKG_CONFIG
AC_USE_SYSTEM_EXTENSIONS

# Checks for header files.
AC_CHECK_HEADERS([ \
	fcntl.h \
	langinfo.h \
	limits.h \
	linux/landlock.h \
	locale.h \
	netdb.h \
	netinet/in.h \
	paths.h \
	poll.h \
	stddef.h \
	stdint.h \
	stdlib.h \
	string.h \
	sys/ioctl.h \
	sys/param.h \
	sys/poll.h \
	sys/socket.h \
	sys/time.h \
	sys/tree.h \
	util.h \
	unistd.h \
	wchar.h \
])

# Checks for typ edefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT64_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Look for library needed for flock.
AC_SEARCH_LIBS(flock, bsd)

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_FSEEKO
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_FUNC_STRERROR_R
AC_FUNC_STRNLEN
AC_CHECK_FUNCS([ \
	dup2 \
	flock \
	getcwd \
	localtime_r \
	memchr \
	memmove \
	memset \
	mkdir \
	munmap \
	nl_langinfo \
	realpath \
	regcomp \
	rmdir \
	setlocale \
	socket \
	strcasecmp \
	strchr \
	strcspn \
	strdup \
	strerror \
	strlcpy \
	strncasecmp \
	strndup \
	strrchr \
	strspn \
	strstr \
	strtol \
	strtoul \
	wcwidth \
])

# Siphash support.
AC_CHECK_FUNCS([SipHash])
AM_CONDITIONAL([HAVE_SIPHASH], [test "x$ac_cv_func_SipHash" = xyes])

# Check for functions with a compatibility implementation.
AC_REPLACE_FUNCS([ \
	asprintf \
	closefrom \
	explicit_bzero \
	fmt_scaled \
	freezero \
	getdtablecount \
	getline \
	getprogname \
	recallocarray \
	reallocarray \
	strlcat \
	strlcpy \
	strndup \
	strsep \
	strtonum \
])

# Always use our getopt because 1) glibc's doesn't enforce argument order 2)
# musl does not set optarg to NULL for flags without arguments (although it is
# not required to, but it is helpful) 3) there are probably other weird
# implementations.
AC_LIBOBJ(getopt)

# Check the platform we're compiling on.
AC_MSG_CHECKING(platform)
case "$host_os" in
	*linux*)
		AC_MSG_RESULT(linux)
		PLATFORM=linux
		;;
	*freebsd*)
		AC_MSG_RESULT(freebsd)
		PLATFORM=freebsd
		;;
	*darwin*)
		AC_MSG_RESULT(darwin)
		PLATFORM=darwin
		;;
	*netbsd*)
		AC_MSG_RESULT(netbsd)
		PLATFORM=netbsd
		;;
	*dragonfly*)
		AC_MSG_RESULT(dragonfly)
		PLATFORM=dragonflybsd
		;;
	*)
		AC_MSG_RESULT(unknown)
		PLATFORM=unknown
		;;
esac
AC_SUBST(PLATFORM)
AM_CONDITIONAL([HOST_FREEBSD], [test "$PLATFORM" = "freebsd"])
AM_CONDITIONAL([HOST_LINUX], [test "$PLATFORM" = "linux"])
AM_CONDITIONAL([HOST_DARWIN], [test "$PLATFORM" = "darwin"])
AM_CONDITIONAL([HOST_NETBSD], [test "$PLATFORM" = "netbsd"])
AM_CONDITIONAL([HOST_DRAGONFLYBSD], [test "$PLATFORM" = "dragonflybsd"])

# Landlock detection.
AC_MSG_CHECKING([for landlock])
AM_CONDITIONAL([HAVE_LINUX_LANDLOCK],
    [test "x$ac_cv_header_linux_landlock_h" = "xyes"])
if test "x$ac_cv_header_linux_landlock_h" = "xyes"; then
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
fi

# Clang sanitizers wrap reallocarray even if it isn't available on the target
# system. When compiled it always returns NULL and crashes the program. To
# detect this we need a more complicated test.
AC_MSG_CHECKING([for working reallocarray])
AC_RUN_IFELSE([AC_LANG_PROGRAM(
		[#include <stdlib.h>],
		[return (reallocarray(NULL, 1, 1) == NULL);]
	)],
	AC_MSG_RESULT(yes),
	[AC_LIBOBJ(reallocarray) AC_MSG_RESULT([no])],
	[AC_LIBOBJ(reallocarray) AC_MSG_RESULT([no])]
)
AC_MSG_CHECKING([for working recallocarray])
AC_RUN_IFELSE([AC_LANG_PROGRAM(
		[#include <stdlib.h>],
		[return (recallocarray(NULL, 1, 1, 1) == NULL);]
	)],
	AC_MSG_RESULT(yes),
	[AC_LIBOBJ(recallocarray) AC_MSG_RESULT([no])],
	[AC_LIBOBJ(recallocarray) AC_MSG_RESULT([no])]
)

# Look for imsg_init in libutil.
AC_SEARCH_LIBS(imsg_init, util, found_imsg_init=yes, found_imsg_init=no)
if test "x$found_imsg_init" = xyes; then
	AC_DEFINE(HAVE_IMSG)
else
	AC_LIBOBJ(imsg)
	AC_LIBOBJ(imsg-buffer)
fi

# libcrypto (via libssl for SHA information)
PKG_CHECK_MODULES(
	LIBCRYPTO,
	libcrypto,
	[
	 	AM_CFLAGS="$LIBCRYPTO_CFLAGS $AM_CFLAGS"
		CFLAGS="$AM_CFLAGS $SAVED_CFLAGS"
		LIBS="$LIBCRYPTO_LIBS $LIBS"
		found_libcrypto=yes
	],
	[
	 	found_libcrypto=no
	]
)

if test "x$found_libcrypto" = "xyes"; then
	AC_DEFINE(HAVE_LIBCRYPTO)
fi

AC_SEARCH_LIBS(uuid_create, , AC_DEFINE(HAVE_BSD_UUID))
AC_SEARCH_LIBS(uuid_create, found_uuid=no, found_uuid=yes)
AC_SEARCH_LIBS(mergesort, , AC_DEFINE(HAVE_BSD_MERGESORT))

# Don't define HAVE_BSD_UUID on darwin (Apple) as this breaks the BSD API.
# Instead, use the UUID implementation wrapper that's in compat/ plus uuid
# ossp
if test "x$found_uuid" = "xyes" -a "x$PLATFORM" != "darwin"; then
	AC_DEFINE(HAVE_BSD_UUID)
else
	PKG_CHECK_MODULES(
		LIBUUID,
		uuid,
		[
			AM_CFLAGS="$LIBUUID_CFLAGS $AM_CFLAGS"
			CFLAGS="$AM_CFLAGS $SAVED_CFLAGS"
			LIBS="$LIBUUID_LIBS $LIBS"
			found_libuuid=yes
		],
		[
			found_libuuid=no
		]
	)

	if test "x$found_libuuid" = "xno"; then
		AC_CHECK_HEADER(
			uuid.h,
			found_libuuid=yes,
			found_libuuid=no)
	fi
fi

if test "x$found_libuuid" = "xno"; then
	AC_MSG_ERROR("*** couldn't find uuid ***")
fi

PKG_CHECK_MODULES(
	ZLIB,
	zlib,
	[
	 	AM_CFLAGS="$ZLIB_CFLAGS $AM_CFLAGS"
		CFLAGS="$AM_CFLAGS $SAVED_CFLAGS"
		LIBS="$ZLIB_LIBS $LIBS"
		found_zlib=yes
	],
	[
	 	found_zlib=no
	]
)

if test "x$found_zlib" = "xno"; then
	AC_CHECK_HEADER(
		zlib.h,
		,
		found_zlib=no)
fi

if test "x$found_zlib" = "xno"; then
	AC_MSG_ERROR("*** couldn't find zlib ***")
fi

if test "$PLATFORM" = "linux"; then
	PKG_CHECK_MODULES(
		LIBMD,
		libmd,
		[
			AM_CFLAGS="$LIBMD_CFLAGS $AM_CFLAGS"
			CFLAGS="$AM_CFLAGS $SAVED_CFLAGS"
			LIBS="$LIBMD_LIBS $LIBS"
		],
		[
			AC_MSG_ERROR("*** couldn't find libmd via pkg-config")
		]
	)
	PKG_CHECK_MODULES(
		LIBBSD,
		libbsd-overlay,
		[
			AM_CFLAGS="$LIBBSD_CFLAGS $AM_CFLAGS"
			CFLAGS="$AM_CFLAGS $SAVED_CFLAGS"
			LIBS="$LIBBSD_LIBS $LIBS"
			found_libbsd=yes
			AC_DEFINE(HAVE_LIBBSD)
		],
		[]
	)
fi

# Look for a suitable queue.h.  We hope libbsd is enough, but that is missing
# SIMPLEQ.
AC_CHECK_DECL(
	SIMPLEQ_INIT,
	found_queue_h=yes,
	found_queue_h=no,
	[#include <sys/queue.h>]
)
AC_CHECK_DECL(
	TAILQ_CONCAT,
	found_queue_h=yes,
	found_queue_h=no,
	[#include <sys/queue.h>]
)
AC_CHECK_DECL(
	TAILQ_PREV,
	found_queue_h=yes,
	found_queue_h=no,
	[#include <sys/queue.h>]
)
AC_CHECK_DECL(
	TAILQ_REPLACE,
	found_queue_h=yes,
	found_queue_h=no,
	[#include <sys/queue.h>]
)
AC_CHECK_DECL(
	SIMPLEQ_ENTRY,
	,
	found_queue_h=no,
	[#include <sys/queue.h>]
)
AC_CHECK_DECL(
	TAILQ_FOREACH_SAFE,
	,
	found_queue_h=no,
	[#include <sys/queue.h>]
)
if test "x$found_queue_h" = xyes; then
	AC_DEFINE(HAVE_QUEUE_H)
fi

# Look for __progname.
AC_MSG_CHECKING(for __progname)
AC_LINK_IFELSE([AC_LANG_SOURCE(
	[
		#include <stdio.h>
		#include <stdlib.h>
		extern char *__progname;
		int main(void) {
			const char *cp = __progname;
			printf("%s\n", cp);
			exit(0);
		}
	])],
	[AC_DEFINE(HAVE___PROGNAME) AC_MSG_RESULT(yes)],
	AC_MSG_RESULT(no)
)

PKG_CHECK_MODULES(
	LIBPANELW,
	panelw,
	found_panel=yes,
	found_panel=no
)

PKG_CHECK_MODULES(
	LIBPANELW,
	gnupanelw,
	found_panel=yes,
	found_panel=no
)

PKG_CHECK_MODULES(
	LIBPANELW,
	panel,
	found_panel=yes,
	found_panel=no
)
if test "x$found_panel" = "xno"; then
	AC_CHECK_LIB(panelw, update_panels,,
		AC_MSG_ERROR([ "*** panelw not found for ncurses. ***"])
	)

	LIBPANELW_LIBS="-lpanelw"
fi

PKG_CHECK_MODULES(
	LIBNCURSES,
	ncursesw,
	found_ncurses=yes,
	found_ncurses=no
)
if test "x$found_ncurses" = xyes; then
	AM_CFLAGS="$LIBNCURSES_CFLAGS $LIBTINFO_CFLAGS $LIBPANELW_CFLAGS $AM_CFLAGS"
	CFLAGS="$LIBNCURSES_CFLAGS $LIBTINFO_CFLAGS $LIBPANELW_CFLAGS $CFLAGS"
	LIBS="$LIBNCURSES_LIBS $LIBTINFO_LIBS $LIBPANELW_LIBS $LIBS"
else
	AC_CHECK_LIB(
		ncursesw,
		setupterm,
		found_ncurses=yes,
		found_ncurses=no
	)
	if test "x$found_ncurses" = xyes; then
		AC_CHECK_HEADER(
			ncurses.h,
			AM_CFLAGS="$LIBPANELW_CFLAGS $AM_CFLAGS"
			CFLAGS="$LIBPANEL_CFLAGS $CFLAGS"
			LIBS="$LIBS -lncursesw $LIBPANELW_LIBS",
			found_ncurses=no
		)
	fi
fi
if test "x$found_ncurses" = xyes; then
	AC_DEFINE(HAVE_NCURSES_H)
else
	# No ncurses, try curses.
	AC_CHECK_LIB(
		cursesw,
		setupterm,
		found_curses=yes,
		found_curses=no
	)
	AC_CHECK_HEADER(
		curses.h,
		,
		found_curses=no)
	if test "x$found_curses" = xyes; then
		AM_CFLAGS="$LIBPANELW_CFLAGS $AM_CFLAGS"
		CFLAGS="$LIBPANEL_CFLAGS $CFLAGS"
		LIBS="$LIBS -lcursesw $LIBPANELW_LIBS"
		AC_DEFINE(HAVE_CURSES_H)
	else
		AC_MSG_ERROR("curses not found")
	fi
fi

# Save our CFLAGS/CPPFLAGS/LDFLAGS for the Makefile and restore the old user
# variables.
AC_SUBST(AM_CPPFLAGS)
CPPFLAGS="$SAVED_CPPFLAGS"
AC_SUBST(AM_CFLAGS)
CFLAGS="$SAVED_CFLAGS"
AC_SUBST(AM_LDFLAGS)
LDFLAGS="$SAVED_LDFLAGS"

AC_CONFIG_FILES([Makefile
		 compat/Makefile
		 libexec/Makefile
		 libexec/got-read-tree/Makefile
		 libexec/got-fetch-pack/Makefile
		 libexec/got-index-pack/Makefile
		 libexec/got-read-blob/Makefile
		 libexec/got-read-commit/Makefile
		 libexec/got-read-gitconfig/Makefile
		 libexec/got-read-gotconfig/Makefile
		 libexec/got-read-object/Makefile
		 libexec/got-read-pack/Makefile
		 libexec/got-read-patch/Makefile
		 libexec/got-read-tag/Makefile
		 libexec/got-send-pack/Makefile
		 got/Makefile
		 gotadmin/Makefile
		 tog/Makefile
		 Makefile.common:Makefile.common.in])
AC_OUTPUT

#                tog/GNUMakefile])
#                regress/GNUMakefile
#                regress/cmdline/GNUMakefile
#                regress/delta/GNUMakefile
#                regress/fetch/GNUMakefile
#                regress/idset/GNUMakefile
#                regress/path/GNUMakefile
#                 gotweb/GNUMakefile
#                 gotweb/libexec/GNUMakefile
#                 gotweb/libexec/got-read-blob/GNUMakefile
#                 gotweb/libexec/got-read-commit/GNUMakefile
#                 gotweb/libexec/got-read-gitconfig/GNUMakefile
#                 gotweb/libexec/got-read-gotconfig/GNUMakefile
#                 gotweb/libexec/got-read-object/GNUMakefile
#                 gotweb/libexec/got-read-pack/GNUMakefile
#                 gotweb/libexec/got-read-tag/GNUMakefile
#                 gotweb/libexec/got-read-tree/GNUMakefile
