pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = pop3

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-storage \
	-DMODULEDIR=\""$(moduledir)"\"

pop3_LDFLAGS = -export-dynamic

# get some functions included which only plugins use. liblib should probably
# be a shared library so this wouldn't be needed..
unused_objects = \
	../lib/mountpoint.o \
	../lib-imap/imap-util.o

libs = \
	$(STORAGE_LIBS) \
	../lib-dict/libdict.a \
	$(unused_objects)

pop3_LDADD = \
	$(libs) \
	$(LIBICONV) \
	$(MODULE_LIBS)

pop3_DEPENDENCIES = $(libs)

pop3_SOURCES = \
	client.c \
	commands.c \
	main.c

headers = \
	capability.h \
	client.h \
	commands.h \
	common.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)/src/pop3
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif
