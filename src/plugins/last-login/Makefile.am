AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage

NOPLUGIN_LDFLAGS =
lib10_last_login_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib10_last_login_plugin.la

lib10_last_login_plugin_la_SOURCES = \
	last-login-plugin.c

noinst_HEADERS = \
	last-login-plugin.h
