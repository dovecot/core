AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/imap \
	-I$(top_srcdir)/src/plugins/stats

imap_moduledir = $(moduledir)

NOPLUGIN_LDFLAGS =
lib95_imap_stats_plugin_la_LDFLAGS = -module -avoid-version

imap_module_LTLIBRARIES = \
	lib95_imap_stats_plugin.la

if DOVECOT_PLUGIN_DEPS
lib95_imap_stats_plugin_la_LIBADD = \
	../stats/lib90_stats_plugin.la
endif

lib95_imap_stats_plugin_la_SOURCES = \
	imap-stats-plugin.c

noinst_HEADERS = \
	imap-stats-plugin.h
