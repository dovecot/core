AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-stats \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage

NOPLUGIN_LDFLAGS =
lib90_stats_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib90_stats_plugin.la

lib90_stats_plugin_la_SOURCES = \
	mail-stats.c \
	mail-stats-fill.c \
	mail-stats-connection.c \
	stats-plugin.c

noinst_HEADERS = \
	mail-stats.h \
	mail-stats-connection.h \
	stats-plugin.h

stats_moduledir = $(moduledir)/stats
stats_module_LTLIBRARIES = libstats_mail.la

libstats_mail_la_LDFLAGS = -module -avoid-version
libstats_mail_la_LIBADD = mail-stats.lo $(LIBDOVECOT)
libstats_mail_la_DEPENDENCIES = mail-stats.lo
libstats_mail_la_SOURCES =
