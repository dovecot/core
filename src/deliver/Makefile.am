pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = deliver

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/lib-storage/index/raw \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DPKG_RUNDIR=\""$(rundir)"\" \
	-DMODULEDIR=\""$(moduledir)"\"

deliver_LDFLAGS = -export-dynamic

# get some functions included which only plugins use. liblib should probably
# be a shared library so this wouldn't be needed..
unused_objects = \
 	../lib/mountpoint.o

libs = \
	../lib-storage/register/libstorage-register.a \
	../lib-storage/list/libstorage_list.a \
	$(STORAGE_LIBS) \
	../lib-imap/libimap.a \
	../lib-mail/libmail.a \
	../lib-dict/libdict.a \
	../lib-charset/libcharset.a \
	../lib/liblib.a \
	$(unused_objects)

deliver_LDADD = \
	$(libs) \
	$(LIBICONV) \
	$(MODULE_LIBS)

deliver_DEPENDENCIES = $(libs)

deliver_SOURCES = \
	auth-client.c \
	deliver.c \
	duplicate.c \
	mail-send.c \
	smtp-client.c

headers = \
	auth-client.h \
	deliver.h \
	duplicate.h \
	mail-send.h \
	smtp-client.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)/src/deliver
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif
