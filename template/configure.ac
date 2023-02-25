AC_INIT([template], 1.0, [op@openbsd.org])
AC_CONFIG_LIBOBJ_DIR(../compat)
AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_ARG_VAR(HOSTCC, [The C compiler on the host.])
AC_ARG_VAR(HOSTCFLAGS, [CFLAGS for the host compiler])

AC_USE_SYSTEM_EXTENSIONS

# When CFLAGS isn't set at this stage and gcc is detected by the macro below,
# autoconf will automatically use CFLAGS="-O2 -g". Prevent that by using an
# empty default.
: ${CFLAGS=""}

# Save user CPPFLAGS, CFLAGS and LDFLAGS. We need to change them because
# AC_CHECK_HEADER doesn't give us any other way to update the include
# paths. But for Makefile.am we want to use AM_CPPFLAGS and friends.
SAVED_CFLAGS="$CFLAGS"

test -n "$HOSTCC"	&& export CC="$HOSTCC"
test -n "$HOSTCFLAGS"	&& export CFLAGS="$SAVED_CFLAGS $HOSTCFLAGS"

AC_PROG_CC
AC_PROG_YACC
PKG_PROG_PKG_CONFIG

PKG_CHECK_MODULES(LIBBSD, libbsd-overlay, [
	AM_CFLAGS="$LIBBSD_CFLAGS $AM_CFLAGS"
	CFLAGS="$AM_CFLAGS $SAVED_CFLAGS"
	LIBS="$LIBBSD_LIBS $LIBS"
	AC_DEFINE(HAVE_LIBBSD)
], [AC_MSG_NOTICE([libbsd not found])])


AM_CPPFLAGS="$CFLAGS"

AC_REPLACE_FUNCS([ \
	asprintf \
	err \
	getprogname \
	reallocarray \
])

AC_CHECK_DECL([TAILQ_REMOVE], [],
    [AC_MSG_ERROR("*** sys/queue.h is missing key defines ***")],
    [#include <sys/queue.h>])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
