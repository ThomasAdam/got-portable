# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([got-portable],
	m4_esyscmd_s(util/got-portable-ver.sh),
	[thomas@xteddy.org])
AC_CONFIG_AUX_DIR(etc)
AC_CONFIG_SRCDIR([lib/rcsutil.h])
AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_DEFINE_UNQUOTED(VERSION, "$VERSION")
AC_SUBST(VERSION)
AC_SUBST(GOT_RELEASE)

AC_USE_SYSTEM_EXTENSIONS
AC_CANONICAL_HOST

AC_CONFIG_SUBDIRS([template])

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

# YACC override
YACC_OVERRIDE="yes"

# Checks for programs.
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
if test -z "$YACC"; then
YACC_OVERRIDE="no"
AC_PROG_YACC
fi
AM_PROG_AR
AC_PROG_RANLIB
PKG_PROG_PKG_CONFIG

if test "$YACC_OVERRIDE" = "yes"; then
	AC_MSG_NOTICE("Using YACC set from environment: $YACC")
fi

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
	sha.h \
	sha1.h \
	sha2.h \
	sha256.h \
	stddef.h \
	stdint.h \
	stdlib.h \
	string.h \
	sys/ioctl.h \
	sys/param.h \
	sys/poll.h \
	sys/queue.h \
	sys/socket.h \
	sys/time.h \
	sys/tree.h \
	util.h \
	unistd.h \
	wchar.h \
])

if test "x$ac_cv_header_sha256_h" = xyes; then
	AC_DEFINE(HAVE_SHA256)
fi

AM_CONDITIONAL([HAVE_SHA2], [test "x$ac_cv_header_sha2_h" = xyes])

# Check for SHA1_DIGEST_LENGTH
AC_CHECK_DECL([SHA1_DIGEST_LENGTH],
	[AC_DEFINE(HAVE_SHA1_AS_SHA1)],
	[
		dnl maybe sha.h is available
		AC_CHECK_DECL([SHA_DIGEST_LENGTH],
			[AC_DEFINE(HAVE_SHA_AS_SHA1)],
			[],
			[#include <sha.h>])
	],
	[
	#include <sys/types.h>
	#include <sha1.h>
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

# Check for ifgroupreq which is only available on BSD.
AC_CHECK_TYPES([struct ifgroupreq])

# Check for sockaddr_storage.  On some systems, ss_len is filled out, although
# this is not mandated by POSIX, and hence systems such as linux, don't have
# it.
AC_CHECK_TYPES([struct sockaddr_storage], [], [], [
#include <sys/types.h>
#include <sys/socket.h>
])

# Same thing as sockaddr_storage above, only now check if the member exists in
# the struct as well.
AC_CHECK_MEMBERS([struct sockaddr_storage.ss_len], , ,
	[ #include <netdb.h>
	  #include <netinet/in.h>
	  #include <sys/socket.h> ]
)

AC_CHECK_MEMBERS([struct sockaddr.sa_len], , ,
	[ #include <netdb.h>
	  #include <netinet/in.h>
	  #include <sys/socket.h> ]
)

# Both checks above will result in:
#
# HAVE_STRUCT_SOCKADDR_AS_LEN
# SS_LEN
#
# Either being defined or not.

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
	setresgid \
	setresuid \
	setproctitle \
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

AM_CONDITIONAL([HAVE_SETPROCTITLE], [test "x$ac_cv_func_setproctitle" = xyes])
AM_CONDITIONAL([HAVE_SETRESGID], [test "x$ac_cv_func_setresgid" = xyes])
AM_CONDITIONAL([HAVE_SETRESUID], [test "x$ac_cv_func_setresuid" = xyes])

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
	*openbsd*)
		AC_MSG_RESULT(netbsd)
		PLATFORM=openbsd
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
AM_CONDITIONAL([HOST_OPENBSD], [test "$PLATFORM" = "openbsd"])
AM_CONDITIONAL([HOST_DRAGONFLYBSD], [test "$PLATFORM" = "dragonflybsd"])

# Look for yacc.
if test "YACC_OVERRIDE" = "yes" && test -n "$YACC" \
	&& ! command -v "$YACC" >/dev/null 2>&1; then
	AC_MSG_ERROR("yacc not found: $YACC")
fi

if test x"$PLATFORM" = "xdarwin"; then
	# Check for and/or set HOMEBREW_PREFIX.  brew is a common way of
	# installing applications.  The other is MacPorts.
	#
	# Before Apple Silicon existed (M1 onward), the paths for applications
	# installed via homebrew was typically /usr/local.  However, with M1
	# onward, this changed to a different path.
	#
	# Rather than hardcode this, check for HOMEBREW_PREFIX in the
	# environment if it's already set, and use it.  Otherwise, check for
	# brew(1) and use that.  If that fails, default to /usr/local
	#
	# This also means that MacPorts should continue to work.
	#
	# But with MacPorts, we should also check --prefix, and use that if it
	# has been supplied.
	#
	# In both cases, the variable HOMEBREW_PREFIX is used for both.
	HB_PREFIX=""
	FOUND_BISON="no"
	GNUBISON=""
	if test -z "$HOMEBREW_PREFIX" -o "$HOMEBREW_PREFIX" = "NONE"; then
		# HOMEBREW_PREFIX not set, check for brew(1)
		if command -v brew >/dev/null 2>&1; then
			AC_MSG_NOTICE("HOMEBREW_PREFIX set via 'brew --prefix'")
			export HOMEBREW_PREFIX="$(brew --prefix)"
		fi

		if test -z "$HOMEBREW_PREFIX" -o "$HOMEBREW_PREFIX" = "NONE"
		then
			# Default.
			if test -z "${prefix}" -o "${prefix}" = "NONE"; then
				export HOMEBREW_PREFIX="/usr/local"
				HB_PREFIX="/usr/local"
				AC_MSG_NOTICE("HOMEBREW_PREFIX defaulting to $HB_PREFIX")
			else
				HB_PREFIX="$(eval echo ${prefix})"
				if test "$HB_PREFIX" = "NONE"; then
					HB_PREFIX="/opt/local"
				else
					AC_MSG_NOTICE("HOMEBREW_PREFIX using --prefix")
				fi
				export HOMEBREW_PREFIX="$HB_PREFIX"
			fi
		fi
	fi

	AC_MSG_NOTICE("HOMEBREW_PREFIX determined as: $HOMEBREW_PREFIX")

	if test "$YACC_OVERRIDE" = "no" && \
		! test -x "${HOMEBREW_PREFIX}/opt/bison/bin/bison"; then
		AC_MSG_WARN([
			     "***********************************************************
			     GNU Bison not found: ${HOMEBREW_PREFIX}/opt/bison/bin/bison
			     ***********************************************************

			     Falling back to checking either /usr/local or \${prefix}"
		])

		FOUND_BISON="no"
		AC_MSG_WARN("Trying ${HB_PREFIX}/opt/bison/bin/bison")
		if test -x "${HB_PREFIX}/opt/bison/bin/bison"; then
			export HOMEBREW_PREFIX="/usr/local"
			FOUND_BISON="yes"
			GNUBISON="${HB_PREFIX}/opt/bison/bin/bison"
		fi

		if test "$FOUND_BISON" = "no"; then
			HB_PREFIX="/opt/local"
			AC_MSG_WARN("Trying ${HB_PREFIX}/bin/bison")

			if test -x "${HB_PREFIX}/bin/bison"; then
				export HOMEBREW_PREFIX="${HB_PREFIX}"
				GNUBISON="${HB_PREFIX}/bin/bison"
				FOUND_BISON="yes"
			fi
		fi
	else
		FOUND_BISON="yes"
		GNUBISON="${HOMEBREW_PREFIX}/opt/bison/bin/bison"
	fi

	if test "$FOUND_BISON" = "no" && test "$YACC_OVERRIDE" = "no"; then
		AC_MSG_ERROR("*** Couldn't find GNU BISON ***")
	fi

	# Override YACC here to point to the GNU version of bison.
	if test "$YACC_OVERRIDE" = "yes"; then
		export YACC="$YACC -y"
	else
		AC_MSG_NOTICE("Found GNU Bison as: $GNUBISON")
		export YACC="${GNUBISON} -y"
	fi
	export LDFLAGS="-L${HOMEBREW_PREFIX}/opt/ncurses/lib -L${HOMEBREW_PREFIX}/opt/openssl@3/lib $LDFLAGS"
	export CPPFLAGS="-I${HOMEBREW_PREFIX}/opt/ncurses/include -I${HOMEBREW_PREFIX}/opt/openssl@3/include $CPPFLAGS"
	export PKG_CONFIG_PATH="${HOMEBREW_PREFIX}/opt/ncurses/lib/pkgconfig"
	export PKG_CONFIG_PATH="$PKG_CONFIG_PATH:${HOMEBREW_PREFIX}/opt/openssl@3/lib/pkgconfig"
fi

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
AM_CONDITIONAL([HAVE_IMSG], [test "x$found_imsg_init" = "xyes"])
if test "x$found_imsg_init" = xno; then
	AC_LIBOBJ(imsg)
	AC_LIBOBJ(imsg-buffer)
fi

# libevent (for gotwebd).  Lifted from tmux.
# Look for libevent. Try libevent_core or libevent with pkg-config first then
# look for the library.
PKG_CHECK_MODULES(
	LIBEVENT_CORE,
	[libevent_core >= 2],
	[
		AM_CPPFLAGS="$LIBEVENT_CORE_CFLAGS $AM_CPPFLAGS"
		CPPFLAGS="$AM_CPPFLAGS $SAVED_CPPFLAGS"
		LIBS="$LIBEVENT_CORE_LIBS $LIBS"
		found_libevent=yes
	],
	found_libevent=no
)
if test x$found_libevent = xno; then
	PKG_CHECK_MODULES(
		LIBEVENT,
		[libevent >= 2],
		[
			AM_CPPFLAGS="$LIBEVENT_CFLAGS $AM_CPPFLAGS"
			CPPFLAGS="$AM_CPPFLAGS $SAVED_CPPFLAGS"
			LIBS="$LIBEVENT_LIBS $LIBS"
			found_libevent=yes
		],
		found_libevent=no
	)
fi
if test x$found_libevent = xno; then
	AC_SEARCH_LIBS(
		event_init,
		[event_core event event-1.4],
		found_libevent=yes,
		found_libevent=no
	)
fi
AC_CHECK_HEADER(
	event2/event.h,
	AC_DEFINE(HAVE_EVENT2_EVENT_H),
	[
		AC_CHECK_HEADER(
			event.h,
			AC_DEFINE(HAVE_EVENT_H),
			found_libevent=no
		)
	]
)
if test "x$found_libevent" = xno; then
	AC_MSG_ERROR("libevent not found")
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
		[
			AC_MSG_ERROR("*** couldn't find libbsd-overlay via pkg-config")
		]

	)
fi

# Look for a suitable queue.h.  We hope libbsd is enough, but that is missing
# some declarations.
AC_CHECK_DECL(
	TAILQ_CONCAT,
	found_queue_h=yes,
	found_queue_h=no,
	[#include <sys/queue.h>]
)
AC_CHECK_DECL(
	TAILQ_PREV,
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
else
	AC_MSG_ERROR("*** sys/queue.h missing key defines ***)
fi

AC_CHECK_DECL(
	RB_GENERATE_STATIC,
	found_sys_tree_h=yes,
	found_sys_tree_h=no,
	[#include <sys/tree.h>]
)

if test "x$found_sys_tree_h" = xyes; then
	AC_DEFINE(HAVE_TREE_H)
else
	AC_MSG_NOTICE("Using compat/tree.h")
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
	AC_CHECK_LIB(panelw, update_panels, [],
		AC_MSG_ERROR([ "*** panelw not found for ncurses. ***"]),
		[-lncurses]
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
		 gotwebd/Makefile
		 tog/Makefile
		 Makefile.common:Makefile.common.in])
AC_OUTPUT

executables="$(eval echo ${exec_prefix}/bin)"
helpers="$(eval echo ${libexecdir})"
manpages="$(eval echo ${mandir})"

echo "
Configured got-portable with:

 Version:      $VERSION

 Prefix:       ${prefix}
 Executables:  ${executables}
 Bison:        $YACC
 Helpers:      ${helpers}
 Man pages:    ${manpages}
"
