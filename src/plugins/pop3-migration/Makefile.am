AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index

NOPLUGIN_LDFLAGS =
lib05_pop3_migration_plugin_la_LDFLAGS = -module -avoid-version

module_LTLIBRARIES = \
	lib05_pop3_migration_plugin.la

lib05_pop3_migration_plugin_la_SOURCES = \
	pop3-migration-plugin.c

noinst_HEADERS = \
	pop3-migration-plugin.h

noinst_PROGRAMS = $(test_programs)

test_programs = \
	test-pop3-migration-plugin

test_libs = \
	$(LIBDOVECOT_STORAGE) \
	$(LIBDOVECOT)
test_deps = \
	$(module_LTLIBRARIES) \
	$(LIBDOVECOT_STORAGE_DEPS) \
	$(LIBDOVECOT_DEPS)

test_pop3_migration_plugin_SOURCES = test-pop3-migration-plugin.c
test_pop3_migration_plugin_LDADD = pop3-migration-plugin.lo $(test_libs)
test_pop3_migration_plugin_DEPENDENCIES = $(test_deps)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
