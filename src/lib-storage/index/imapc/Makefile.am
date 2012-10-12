noinst_LTLIBRARIES = libstorage_imapc.la
module_LTLIBRARIES = lib20_imapc_plugin.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-imap-client \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/list \
	-I$(top_srcdir)/src/lib-storage/index

NOPLUGIN_LDFLAGS =
lib20_imapc_plugin_la_LDFLAGS = -module -avoid-version

libstorage_imapc_la_SOURCES = \
	imapc-settings.c \
	imapc-setting-storage.c

lib20_imapc_plugin_la_SOURCES = \
	imapc-list.c \
	imapc-mail.c \
	imapc-mail-fetch.c \
	imapc-mailbox.c \
	imapc-plugin.c \
	imapc-save.c \
	imapc-sync.c \
	imapc-storage.c

lib20_imapc_plugin_la_LIBADD = \
	../../../lib-imap-client/libimap_client.la \
	../../../lib-ssl-iostream/libssl_iostream.la

headers = \
	imapc-list.h \
	imapc-mail.h \
	imapc-settings.h \
	imapc-storage.h \
	imapc-sync.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

noinst_HEADERS = \
	imapc-plugin.h
