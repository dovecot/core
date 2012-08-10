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

if !BUILD_SHARED_LIBS
unused_objects = \
	../lib-imap/imap-util.o \
	../lib-storage/mail-search-parser-imap.o
endif

pop3_LDADD = \
	$(unused_objects) \
	$(LIBDOVECOT_STORAGE) \
	$(LIBDOVECOT) \
	$(MODULE_LIBS)
pop3_DEPENDENCIES = \
	$(unused_objects) \
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
