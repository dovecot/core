pkglibexecdir = $(libexecdir)/dovecot

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-DPKG_RUNDIR=\""$(rundir)"\"

lib20_expire_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib20_expire_plugin.la

lib20_expire_plugin_la_SOURCES = \
	expire-env.c \
	expire-plugin.c

noinst_HEADERS = \
	auth-client.h \
	expire-env.h \
	expire-plugin.h \
	expire-settings.h

pkglibexec_PROGRAMS = expire-tool

expire_tool_SOURCES = \
	auth-client.c \
	expire-settings.c \
	expire-tool.c

libs = \
	$(top_builddir)/src/lib-storage/libdovecot-storage.la \
	$(top_builddir)/src/lib-dovecot/libdovecot.la

expire_tool_LDADD = $(libs)

expire_tool_DEPENDENCIES = $(libs)
