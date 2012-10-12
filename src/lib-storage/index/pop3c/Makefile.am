noinst_LTLIBRARIES = libstorage_pop3c.la
module_LTLIBRARIES = lib20_pop3c_plugin.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-dns \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index

NOPLUGIN_LDFLAGS =
lib20_pop3c_plugin_la_LDFLAGS = -module -avoid-version

libstorage_pop3c_la_SOURCES = \
	pop3c-settings.c \
	pop3c-setting-storage.c

lib20_pop3c_plugin_la_SOURCES = \
	pop3c-client.c \
	pop3c-mail.c \
	pop3c-plugin.c \
	pop3c-storage.c \
	pop3c-sync.c

lib20_pop3c_plugin_la_LIBADD = \
	../../../lib-ssl-iostream/libssl_iostream.la

headers = \
	pop3c-client.h \
	pop3c-settings.h \
	pop3c-storage.h \
	pop3c-sync.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

noinst_HEADERS = \
	pop3c-plugin.h
