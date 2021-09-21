SUBDIRS = compat libexec got tog gotadmin

AM_CPPFLAGS += -DGOT_VERSION='"@VERSION'" \
	-DGOT_VERSION_NUMBER='"@VERSION"' \
	-DGOT_LIBEXECDIR="${bindir}" \
	-I$(top_srcdir)/lib \
	-I$(top_srcdir)/compat \
	-I$(top_srcdir)/include

LDADD = $(LIBOBJS)

# FIXME: enable via --enable-debug.  Hard-code for now.
AM_CFLAGS += -g
AM_CFLAGS += -Wno-long-long -Wall -W -Wformat=2
AM_CFLAGS += -Wmissing-prototypes -Wstrict-prototypes -Wmissing-declarations
AM_CFLAGS += -Wwrite-strings -Wshadow -Wpointer-arith -Wsign-compare
AM_CFLAGS += -Wundef -Wbad-function-cast -Winline -Wcast-align
AM_CFLAGS += -Wdeclaration-after-statement -Wno-pointer-sign -Wno-attributes
AM_CFLAGS += -Wno-unused-result

tests:
	$(MAKE) -C regress/cmdline -f Makefile.linux
