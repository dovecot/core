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
	../lib/mountpoint.o \
	../lib-imap/imap-util.o
endif

libs = \
	$(LIBDOVECOT_STORAGE) \
	$(LIBDOVECOT) \
	$(unused_objects)

pop3_LDADD = $(libs) $(MODULE_LIBS)
pop3_DEPENDENCIES = $(libs)

pop3_SOURCES = \
	client.c \
	commands.c \
	main.c \
	pop3-settings.c

headers = \
	capability.h \
	client.h \
	commands.h \
	common.h \
	pop3-settings.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)/src/pop3
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif
