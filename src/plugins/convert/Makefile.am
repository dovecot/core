pkglibexecdir = $(libexecdir)/dovecot

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-DPKG_RUNDIR=\""$(rundir)"\"

lib20_convert_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib20_convert_plugin.la

lib20_convert_plugin_la_SOURCES = \
	convert-storage.c \
	convert-plugin.c

noinst_HEADERS = \
	convert-settings.h \
	convert-storage.h \
	convert-plugin.h

pkglibexec_PROGRAMS = convert-tool

convert_tool_SOURCES = \
	convert-settings.c \
	convert-tool.c

common_objects = \
	convert-storage.lo

libs = \
	$(top_builddir)/src/lib-storage/libdovecot-storage.la \
	$(top_builddir)/src/lib-dovecot/libdovecot.la

convert_tool_LDADD = \
	$(common_objects) \
	$(libs)

convert_tool_DEPENDENCIES = $(libs) $(common_objects)
