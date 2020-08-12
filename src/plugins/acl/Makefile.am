doveadm_moduledir = $(moduledir)/doveadm

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/list \
	-I$(top_srcdir)/src/doveadm

NOPLUGIN_LDFLAGS =
lib10_doveadm_acl_plugin_la_LDFLAGS = -module -avoid-version
lib01_acl_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib01_acl_plugin.la

lib01_acl_plugin_la_SOURCES = \
	acl-api.c \
	acl-attributes.c \
	acl-backend.c \
	acl-backend-vfile.c \
	acl-backend-vfile-acllist.c \
	acl-backend-vfile-update.c \
	acl-cache.c \
	acl-global-file.c \
	acl-lookup-dict.c \
	acl-mailbox.c \
	acl-mailbox-list.c \
	acl-plugin.c \
	acl-shared-storage.c \
	acl-storage.c

noinst_HEADERS = \
	acl-backend-vfile.h \
	acl-shared-storage.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = \
	acl-api.h \
	acl-api-private.h \
	acl-cache.h \
	acl-global-file.h \
	acl-lookup-dict.h \
	acl-plugin.h \
	acl-storage.h

doveadm_module_LTLIBRARIES = \
	lib10_doveadm_acl_plugin.la

lib10_doveadm_acl_plugin_la_SOURCES = \
	doveadm-acl.c

test_programs = \
	test-acl

test_libs = \
	$(module_LTLIBRARIES) \
	$(LIBDOVECOT_STORAGE) \
	$(LIBDOVECOT)
test_deps = \
	$(module_LTLIBRARIES) \
	$(LIBDOVECOT_STORAGE_DEPS) \
	$(LIBDOVECOT_DEPS)

test_acl_SOURCES = test-acl.c
test_acl_LDADD = $(test_libs)
test_acl_DEPENDENCIES = $(test_deps)

check-local:
	for bin in $(test_programs); do \
	  if ! env $(test_options) $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done

noinst_PROGRAMS = $(test_programs)
