AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-auth-client \
	-I$(top_srcdir)/src/lib-doveadm \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/doveadm

doveadm_moduledir = $(moduledir)/doveadm

lib20_doveadm_dsync_replication_plugin_la_LDFLAGS = -module -avoid-version

doveadm_module_LTLIBRARIES = lib20_doveadm_dsync_replication_plugin.la

lib20_doveadm_dsync_replication_plugin_la_SOURCES = \
	doveadm-dsync-replication-plugin.c

noinst_HEADERS = \
	doveadm-dsync-replication-plugin.h
