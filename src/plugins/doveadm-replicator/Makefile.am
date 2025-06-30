AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-doveadm \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/doveadm

doveadm_moduledir = $(moduledir)/doveadm

lib20_doveadm_replicator_plugin_la_LDFLAGS = -module -avoid-version

doveadm_module_LTLIBRARIES = lib20_doveadm_replicator_plugin.la

lib20_doveadm_replicator_plugin_la_SOURCES = \
	doveadm-replicator.c \
	doveadm-replicator-plugin.c

noinst_HEADERS = \
	doveadm-replicator.h \
	doveadm-replicator-plugin.h
