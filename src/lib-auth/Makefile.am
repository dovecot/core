noinst_LTLIBRARIES = libauth.la

AM_CPPFLAGS = \
	$(LIBSODIUM_CFLAGS) \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-otp

libauth_la_SOURCES = \
	crypt-blowfish.c \
	mycrypt.c \
	auth-scram.c \
	auth-scram-client.c \
	auth-scram-server.c \
	password-scheme.c \
	password-scheme-crypt.c \
	password-scheme-md5crypt.c \
	password-scheme-scram.c \
	password-scheme-otp.c \
	password-scheme-pbkdf2.c \
	password-scheme-sodium.c

libauth_la_LIBADD = \
	$(LIBSODIUM_LIBS) \
	$(CRYPT_LIBS)

headers = \
	mycrypt.h \
	auth-scram.h \
	auth-scram-client.h \
	auth-scram-server.h \
	password-scheme.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

noinst_HEADERS = crypt-blowfish.h

test_programs = \
	test-password-scheme \
	test-auth-scram

noinst_PROGRAMS = $(test_programs)

test_libs = \
	$(noinst_LTLIBRARIES) \
	../lib-test/libtest.la \
	../lib/liblib.la \
	$(MODULE_LIBS)

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

test_auth_scram_SOURCES = \
	test-auth-scram.c
test_auth_scram_LDFLAGS = -export-dynamic
test_auth_scram_LDADD = \
	$(test_libs) \
        ../lib-otp/libotp.la
test_auth_scram_DEPENDENCIES = \
	$(test_deps)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
