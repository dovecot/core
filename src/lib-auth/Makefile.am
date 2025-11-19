include $(top_srcdir)/Makefile.test.include

noinst_LTLIBRARIES = libauth-crypt.la libauth.la
if HAVE_GSSAPI
noinst_LTLIBRARIES += libauth-gssapi.la
endif

AM_CPPFLAGS = \
	$(LIBSODIUM_CFLAGS) \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-otp

libauth_la_SOURCES = \
	auth-digest.c \
	auth-gs2.c \
	auth-scram.c \
	auth-scram-client.c \
	auth-scram-server.c \
	crypt-blowfish.c \
	password-scheme.c \
	password-scheme-md5crypt.c \
	password-scheme-scram.c \
	password-scheme-otp.c \
	password-scheme-pbkdf2.c

libauth_crypt_la_SOURCES = \
	mycrypt.c \
	password-scheme-crypt.c \
	password-scheme-sodium.c

libauth_crypt_la_LIBADD = \
	$(LIBSODIUM_LIBS) \
	$(CRYPT_LIBS)

libauth_gssapi_la_SOURCES = \
	auth-gssapi.c

headers = \
	mycrypt.h \
	auth-digest.h \
	auth-gs2.h \
	auth-gssapi.h \
	auth-scram.h \
	auth-scram-client.h \
	auth-scram-server.h \
	password-scheme.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

noinst_HEADERS = crypt-blowfish.h \
	password-scheme-private.h

test_programs = \
	test-password-scheme \
	test-auth-gs2 \
	test-auth-scram

test_libs = \
	$(noinst_LTLIBRARIES) \
        ../lib-otp/libotp.la \
	../lib-test/libtest.la \
	../lib/liblib.la \
	$(LIBDOVECOT_TEST_LIBS)

test_deps = \
	$(noinst_LTLIBRARIES) \
	../lib-test/libtest.la \
	../lib/liblib.la

test_password_scheme_SOURCES = \
	test-password-scheme.c
test_password_scheme_LDFLAGS = -export-dynamic
test_password_scheme_LDADD = \
	$(test_libs) \
        ../lib-otp/libotp.la \
        $(CRYPT_LIBS) \
        $(LIBSODIUM_LIBS)
test_password_scheme_DEPENDENCIES = \
	../lib-otp/libotp.la \
	$(test_deps)

test_auth_gs2_SOURCES = \
	test-auth-gs2.c
test_auth_gs2_LDFLAGS = -export-dynamic
test_auth_gs2_LDADD = \
	$(test_libs)
test_auth_gs2_DEPENDENCIES = \
	$(test_deps)

test_auth_scram_SOURCES = \
	test-auth-scram.c
test_auth_scram_LDFLAGS = -export-dynamic
test_auth_scram_LDADD = \
	$(test_libs) \
        ../lib-otp/libotp.la
test_auth_scram_DEPENDENCIES = \
	$(test_deps)
