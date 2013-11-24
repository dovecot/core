AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage

NOPLUGIN_LDFLAGS =
lib10_mail_filter_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib10_mail_filter_plugin.la

lib10_mail_filter_plugin_la_SOURCES = \
	mail-filter-plugin.c \
	istream-ext-filter.c \
	ostream-ext-filter.c

noinst_HEADERS = \
	istream-ext-filter.h \
	ostream-ext-filter.h \
	mail-filter-plugin.h
