pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = anvil

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master

anvil_LDADD = \
	$(LIBDOVECOT) \
	$(MODULE_LIBS) \
	$(RAND_LIBS)
anvil_DEPENDENCIES = $(LIBDOVECOT_DEPS)

anvil_SOURCES = \
	main.c \
	anvil-connection.c \
	anvil-settings.c \
	connect-limit.c \
	penalty.c

noinst_HEADERS = \
	anvil-connection.h \
	common.h \
	connect-limit.h \
	penalty.h
