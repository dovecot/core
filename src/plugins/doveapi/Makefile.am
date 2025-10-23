doveadm_moduledir = $(moduledir)/doveadm

pkglibexecdir = $(libexecdir)/dovecot

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-smtp \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-imap-client \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/lib-storage/index/imapc \
	-I$(top_srcdir)/src/lib-storage/index/maildir \
	-I$(top_srcdir)/src/lib-program-client \
	-I$(top_srcdir)/src/lib-doveadm \
	-I$(top_srcdir)/src/lib-var-expand \
	-I$(top_srcdir)/src/doveadm \
	$(LIBTIRPC_CFLAGS)

    lib10_doveadm_doveapi_plugin_la_LDFLAGS = -module -avoid-version

    doveadm_module_LTLIBRARIES = \
	lib10_doveadm_doveapi_plugin.la

lib10_doveadm_doveapi_plugin_la_SOURCES = \
	doveadm-doveapi.c