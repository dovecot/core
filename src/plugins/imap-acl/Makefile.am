AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/lib-storage/index/imapc \
	-I$(top_srcdir)/src/imap \
	-I$(top_srcdir)/src/plugins/acl \
	-I$(top_srcdir)/src/lib-imap-client \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-var-expand

imap_moduledir = $(moduledir)

NOPLUGIN_LDFLAGS =
lib02_imap_acl_plugin_la_LDFLAGS = -module -avoid-version

imap_module_LTLIBRARIES = \
	lib02_imap_acl_plugin.la

if DOVECOT_PLUGIN_DEPS
lib02_imap_acl_plugin_la_LIBADD = \
	../acl/lib01_acl_plugin.la
endif

lib02_imap_acl_plugin_la_SOURCES = \
	imap-acl-plugin.c

noinst_HEADERS = \
	imap-acl-plugin.h
