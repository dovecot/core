pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = pop3

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-storage

pop3_LDFLAGS = -export-dynamic

pop3_LDADD = \
	$(LIBDOVECOT_STORAGE) \
	$(LIBDOVECOT)
pop3_DEPENDENCIES = \
	$(LIBDOVECOT_STORAGE_DEPS) \
	$(LIBDOVECOT_DEPS)

pop3_SOURCES = \
	main.c \
	pop3-client.c \
	pop3-commands.c \
	pop3-settings.c

headers = \
	pop3-capability.h \
	pop3-client.h \
	pop3-commands.h \
	pop3-common.h \
	pop3-settings.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
