pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = deliver

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/lib-storage/index/raw \
	-DPKG_RUNDIR=\""$(rundir)"\"

deliver_LDFLAGS = -export-dynamic

libs = \
	../lib-storage/libdovecot-storage.la \
	../lib-dovecot/libdovecot.la

deliver_LDADD = $(libs)

deliver_DEPENDENCIES = $(libs)

deliver_SOURCES = \
	deliver.c \
	deliver-settings.c \
	duplicate.c \
	mail-send.c \
	smtp-client.c

headers = \
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
