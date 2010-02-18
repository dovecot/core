AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/imap \
	-I$(top_srcdir)/src/plugins/zlib

imap_moduledir = $(moduledir)

lib30_imap_zlib_plugin_la_LDFLAGS = -module -avoid-version

imap_module_LTLIBRARIES = \
	lib30_imap_zlib_plugin.la

if DOVECOT_PLUGIN_DEPS
lib30_imap_zlib_plugin_la_LIBADD = \
	../zlib/lib20_zlib_plugin.la
endif

lib30_imap_zlib_plugin_la_SOURCES = \
	imap-zlib-plugin.c

noinst_HEADERS = \
	imap-zlib-plugin.h
