doveadm_moduledir = $(moduledir)/doveadm

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/doveadm

lib10_doveadm_acl_plugin_la_LDFLAGS = -module -avoid-version
lib01_acl_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib01_acl_plugin.la

lib01_acl_plugin_la_SOURCES = \
	acl-api.c \
	acl-backend.c \
	acl-backend-vfile.c \
	acl-backend-vfile-acllist.c \
	acl-cache.c \
	acl-lookup-dict.c \
	acl-mailbox.c \
	acl-mailbox-list.c \
	acl-plugin.c \
	acl-shared-storage.c \
	acl-storage.c

noinst_HEADERS = \
	acl-api.h \
	acl-api-private.h \
	acl-backend-vfile.h \
	acl-cache.h \
	acl-lookup-dict.h \
	acl-plugin.h \
	acl-shared-storage.h \
	acl-storage.h

doveadm_module_LTLIBRARIES = \
	lib10_doveadm_acl_plugin.la

lib10_doveadm_acl_plugin_la_SOURCES = \
	doveadm-acl.c
