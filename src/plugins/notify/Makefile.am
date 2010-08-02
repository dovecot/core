AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/lib-storage/index/maildir

lib15_notify_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib15_notify_plugin.la

lib15_notify_plugin_la_SOURCES = \
	notify-plugin.c \
	notify-storage.c

headers = \
	notify-plugin.h \
	notify-plugin-private.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
