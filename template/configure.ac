AC_INIT([template], 1.0, [op@openbsd.org])
AC_CONFIG_LIBOBJ_DIR(../compat)
AM_INIT_AUTOMAKE([foreign subdir-objects])

AC_ARG_VAR(HOSTCC, [The C compiler on the host.])
AC_ARG_VAR(HOSTCFLAGS, [CFLAGS for the host compiler])

# When CFLAGS isn't set at this stage and gcc is detected by the macro below,
# autoconf will automatically use CFLAGS="-O2 -g". Prevent that by using an
# empty default.
: ${CFLAGS=""}

# Save user CPPFLAGS, CFLAGS and LDFLAGS. We need to change them because
# AC_CHECK_HEADER doesn't give us any other way to update the include
# paths. But for Makefile.am we want to use AM_CPPFLAGS and friends.
SAVED_CFLAGS="$CFLAGS"

# YACC override
YACC_OVERRIDE="yes"

test -n "$HOSTCC"	&& export CC="$HOSTCC"
test -n "$HOSTCFLAGS"	&& export CFLAGS="$SAVED_CFLAGS $HOSTCFLAGS"

AC_PROG_CC

if test -z "$YACC"; then
YACC_OVERRIDE="no"
AC_PROG_YACC
fi

if test "$YACC_OVERRIDE" = "yes"; then
	AC_MSG_NOTICE("Using YACC set from environment: $YACC")
fi

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

echo "BISON IS: $YACC"
