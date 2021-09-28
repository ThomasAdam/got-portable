SUBDIRS = compat libexec got tog gotadmin

include $(top_builddir)/Makefile.common

EXTRA_DIST = CHANGES CHANGELOG

LDADD = $(LIBOBJS)

tests:
	$(MAKE) -C regress/cmdline -f Makefile.linux
