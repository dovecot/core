pkglibexecdir = $(libexecdir)/dovecot

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage

lib20_convert_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib20_convert_plugin.la

lib20_convert_plugin_la_SOURCES = \
	convert-storage.c \
	convert-plugin.c

noinst_HEADERS = \
	convert-storage.h \
	convert-plugin.h

pkglibexec_PROGRAMS = convert-tool

convert_tool_SOURCES = \
	convert-tool.c

common_objects = \
	convert-storage.lo

libs = \
	$(LIBDOVECOT_STORAGE) \
	$(LIBDOVECOT)

convert_tool_LDADD = \
	$(MODULE_LIBS) \
	$(common_objects) \
	$(libs)

convert_tool_DEPENDENCIES = $(libs) $(common_objects)
