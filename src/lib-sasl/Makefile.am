noinst_LTLIBRARIES = libsasl.la
if HAVE_GSSAPI
noinst_LTLIBRARIES += libsasl-gssapi.la
endif

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-oauth2 \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-json \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-otp \
	-I$(top_srcdir)/src/lib-auth \
	-DTEST_WINBIND_HELPER_PATH=\""$(abs_builddir)/ntlm_dummy"\"

client_mechanisms = \
	dsasl-client-mech-anonymous.c \
	dsasl-client-mech-cram-md5.c \
	dsasl-client-mech-digest-md5.c \
	dsasl-client-mech-external.c \
	dsasl-client-mech-login.c \
	dsasl-client-mech-oauthbearer.c \
	dsasl-client-mech-otp.c \
	dsasl-client-mech-plain.c \
	dsasl-client-mech-scram.c

server_mechanisms = \
	sasl-server-mech-anonymous.c \
	sasl-server-mech-cram-md5.c \
	sasl-server-mech-digest-md5.c \
	sasl-server-mech-external.c \
	sasl-server-mech-login.c \
	sasl-server-mech-oauth2.c \
	sasl-server-mech-otp.c \
	sasl-server-mech-plain.c \
	sasl-server-mech-scram.c \
	sasl-server-mech-winbind.c

libsasl_la_SOURCES = \
	sasl-oauth2.c \
	$(client_mechanisms) \
	dsasl-client.c \
	$(server_mechanisms) \
	sasl-server-mech.c \
	sasl-server-request.c \
	sasl-server.c
libsasl_la_DEPENDENCIES = \
	../lib-json/libjson.la \
	../lib-auth/libauth.la \
	../lib-oauth2/liboauth2.la

if HAVE_GSSAPI
libsasl_gssapi_la_SOURCES = \
	sasl-server-mech-gssapi.c
libsasl_gssapi_la_LIBADD = $(KRB5_LIBS)
libsasl_gssapi_la_CPPFLAGS = $(AM_CPPFLAGS) $(KRB5_CFLAGS)
libsasl_gssapi_la_DEPENDENCIES = \
	libsasl.la \
	../lib-auth/libauth-gssapi.la
endif

headers = \
	sasl-common.h \
	sasl-oauth2.h \
	dsasl-client.h \
	dsasl-client-private.h \
	sasl-server.h \
	sasl-server-gssapi.h \
	sasl-server-oauth2.h \
	sasl-server-protected.h \
	sasl-server-private.h \
	sasl-server-mech-scram.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

noinst_HEADERS =\
	dsasl-client-mech-ntlm-dummy.h

test_programs = \
	test-sasl-oauth2 \
	test-sasl-client \
	test-sasl-authentication

fuzz_programs =
if USE_FUZZER
fuzz_programs += \
        fuzz-sasl-authentication
endif

noinst_PROGRAMS = $(test_programs) ntlm_dummy $(fuzz_programs)

test_libs = \
	libsasl.la \
	../lib-auth/libauth-crypt.la \
	../lib-auth/libauth.la \
	../lib-oauth2/liboauth2.la \
	../lib-otp/libotp.la \
	../lib-json/libjson.la \
	../lib-test/libtest.la \
	../lib/liblib.la

test_deps = $(test_libs)

test_sasl_oauth2_SOURCES = test-sasl-oauth2.c
test_sasl_oauth2_LDADD = $(test_libs)
test_sasl_oauth2_DEPENDENCIES = $(test_deps)

test_sasl_client_SOURCES = test-sasl-client.c
test_sasl_client_LDADD = $(test_libs)
test_sasl_client_DEPENDENCIES = $(test_deps)

test_sasl_authentication_SOURCES = \
	dsasl-client-mech-ntlm-dummy.c \
	test-sasl-authentication.c
test_sasl_authentication_LDADD = $(test_libs)
test_sasl_authentication_DEPENDENCIES = $(test_deps)

ntlm_dummy_SOURCES = ntlm_dummy.c
ntlm_dummy_LDADD = ../lib/liblib.la
ntlm_dummy_DEPENDENCIES = ../lib/liblib.la

nodist_EXTRA_fuzz_sasl_authentication_SOURCES = force-cxx-linking.cxx
fuzz_sasl_authentication_CPPFLAGS = $(FUZZER_CPPFLAGS)
fuzz_sasl_authentication_LDFLAGS = $(FUZZER_LDFLAGS)
fuzz_sasl_authentication_SOURCES = \
	dsasl-client-mech-ntlm-dummy.c \
	fuzz-sasl-authentication.c
fuzz_sasl_authentication_LDADD = $(test_libs)
fuzz_sasl_authentication_DEPENDENCIES = $(test_deps)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
