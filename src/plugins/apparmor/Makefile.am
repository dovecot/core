AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage

NOPLUGIN_LDFLAGS =
lib01_apparmor_plugin_la_LDFLAGS = -module -avoid-version
lib01_apparmor_plugin_la_LIBADD = $(APPARMOR_LIBS)
lib01_apparmor_plugin_la_SOURCES = \
	apparmor-plugin.c

module_LTLIBRARIES = \
	lib01_apparmor_plugin.la
