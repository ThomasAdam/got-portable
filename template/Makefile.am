noinst_PROGRAMS = template

include $(top_builddir)/Makefile.common

template_SOURCES = template.c \
	parse.y

template_DEPENDENCIES = $(top_builddir)/compat/libopenbsd-compat.a

LDADD = -L$(top_builddir)/compat -lopenbsd-compat -lpthread -lm
if HOST_FREEBSD
LDADD += -lmd
endif
