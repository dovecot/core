pkglibexecdir = $(libexecdir)/dovecot

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index

lib20_expire_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib20_expire_plugin.la

lib20_expire_plugin_la_SOURCES = \
	expire-env.c \
	expire-plugin.c

noinst_HEADERS = \
	expire-env.h \
	expire-plugin.h

pkglibexec_PROGRAMS = expire-tool

expire_tool_SOURCES = \
	expire-tool.c

if !BUILD_SHARED_LIBS
unused_objects = \
	$(top_builddir)/src/lib/mountpoint.o
endif

libs = \
	expire-env.lo \
	$(LIBDOVECOT_STORAGE) \
	$(unused_objects)

expire_tool_LDADD = $(libs) $(LIBDOVECOT) $(MODULE_LIBS)
expire_tool_DEPENDENCIES = $(libs) $(LIBDOVECOT_DEPS)
