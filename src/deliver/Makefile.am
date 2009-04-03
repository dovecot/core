pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = deliver

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/lib-storage/index/raw \
	-DBINDIR=\""$(bindir)"\" \
	-DSYSCONFDIR=\""$(sysconfdir)"\" \
	-DPKG_RUNDIR=\""$(rundir)"\" \
	-DMODULEDIR=\""$(moduledir)"\"

deliver_LDFLAGS = -export-dynamic

libs = \
	../lib-storage/libdovecot-storage.la \
	../lib-dovecot/libdovecot.la

deliver_LDADD = \
	$(libs) \
	$(LIBICONV) \
	$(MODULE_LIBS)

deliver_DEPENDENCIES = $(libs)

deliver_SOURCES = \
	auth-client.c \
	deliver.c \
	deliver-settings.c \
	duplicate.c \
	mail-send.c \
	smtp-client.c

headers = \
	auth-client.h \
	deliver.h \
	deliver-settings.h \
	duplicate.h \
	mail-send.h \
	smtp-client.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)/src/deliver
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif
