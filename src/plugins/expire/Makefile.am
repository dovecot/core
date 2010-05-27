doveadm_moduledir = $(moduledir)/doveadm

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
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/doveadm

lib10_doveadm_expire_plugin_la_LDFLAGS = -module -avoid-version
lib20_expire_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib20_expire_plugin.la

lib20_expire_plugin_la_SOURCES = \
	expire-set.c \
	expire-plugin.c

noinst_HEADERS = \
	expire-set.h \
	expire-plugin.h

doveadm_module_LTLIBRARIES = \
	lib10_doveadm_expire_plugin.la

lib10_doveadm_expire_plugin_la_SOURCES = \
	doveadm-expire.c
