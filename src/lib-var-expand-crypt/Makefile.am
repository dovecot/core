include $(top_srcdir)/Makefile.test.include

module_LTLIBRARIES = var_expand_crypt.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-var-expand \
	-I$(top_srcdir)/src/lib-dcrypt

var_expand_crypt_la_SOURCES = \
	var-expand-crypt.c

NOPLUGIN_LDFLAGS =
var_expand_crypt_la_LDFLAGS = $(MODULE_LIBS) -avoid-version -module

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs = \
	test-var-expand-crypt

test_libs = \
	$(LIBUNWIND_LIBS) \
	$(module_LTLIBRARIES) \
	../lib-dcrypt/libdcrypt.la \
	../lib-var-expand/libvar_expand.la \
	../lib-regex/libdregex.la \
	../lib-json/libjson.la \
	../lib-settings/libsettings.la \
	../lib-dns/libdns.la \
	../lib-test/libtest.la \
	../lib/liblib.la

test_var_expand_crypt_SOURCES = test-var-expand-crypt.c
test_var_expand_crypt_LDADD = $(test_libs) $(SSL_LIBS) $(LIBDOVECOT_TEST_LIBS)
test_var_expand_crypt_DEPENDENCIES = $(module_LTLIBRARIES)
test_var_expand_crypt_LDFLAGS = -static
if HAVE_WHOLE_ARCHIVE
test_var_expand_crypt_LDFLAGS += -export-dynamic -Wl,$(LD_WHOLE_ARCHIVE),../lib/.libs/liblib.a,../lib-json/.libs/libjson.a,../lib-ssl-iostream/.libs/libssl_iostream.a,$(LD_NO_WHOLE_ARCHIVE)
endif

test_var_expand_crypt_CFLAGS = $(AM_CFLAGS) \
	-DDCRYPT_BUILD_DIR=\"$(top_builddir)/src/lib-dcrypt\"
