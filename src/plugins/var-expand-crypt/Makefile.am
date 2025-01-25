AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-dcrypt

NOPLUGIN_LDFLAGS =
lib20_var_expand_crypt_la_LDFLAGS = -module -avoid-version
lib20_auth_var_expand_crypt_la_LDFLAGS = -module -avoid-version

auth_moduledir = $(moduledir)/auth

module_LTLIBRARIES = \
	lib20_var_expand_crypt.la

auth_module_LTLIBRARIES = \
	lib20_auth_var_expand_crypt.la

lib20_auth_var_expand_crypt_la_SOURCES = \
	var-expand-crypt-plugin.c

lib20_var_expand_crypt_la_SOURCES = \
	var-expand-crypt-plugin.c

lib20_var_expand_crypt_la_LIBADD = \
       $(top_builddir)/src/lib/liblib.la \
       $(top_builddir)/src/lib-json/libjson.la \
       $(top_builddir)/src/lib-dcrypt/libdcrypt.la \
       $(top_builddir)/src/lib-var-expand/libvar_expand.la

test_programs = test-var-expand-crypt

test_var_expand_crypt_CFLAGS = \
	-DDCRYPT_BUILD_DIR=\"$(top_builddir)/src/lib-dcrypt\"
test_var_expand_crypt_SOURCES = \
	test-var-expand-crypt.c
test_var_expand_crypt_LDADD = \
	$(LIBDOVECOT) \
	lib20_auth_var_expand_crypt.la
test_var_expand_crypt_DEPENDENCIES = \
	$(LIBDOVECOT_DEPS) \
	lib20_auth_var_expand_crypt.la

lib20_auth_var_expand_crypt_la_LIBADD = \
       $(top_builddir)/src/lib/liblib.la \
       $(top_builddir)/src/lib-json/libjson.la \
       $(top_builddir)/src/lib-dcrypt/libdcrypt.la \
       $(top_builddir)/src/lib-var-expand/libvar_expand.la

check-local:
	for bin in $(test_programs); do \
	  if ! env $(test_options) $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done

noinst_PROGRAMS = $(test_programs)
