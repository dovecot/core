noinst_LTLIBRARIES = libhttp.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-dns \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-master

libhttp_la_SOURCES = \
	http-date.c \
	http-url.c \
	http-parser.c \
	http-header.c \
	http-header-parser.c \
	http-transfer-chunked.c \
	http-auth.c \
	http-message-parser.c \
	http-request.c \
	http-request-parser.c \
	http-response.c \
	http-response-parser.c \
	http-client-request.c \
	http-client-connection.c \
	http-client-peer.c \
	http-client-queue.c \
	http-client-host.c \
	http-client.c \
	http-server-response.c \
	http-server-request.c \
	http-server-connection.c \
	http-server.c

headers = \
	http-common.h \
	http-date.h \
	http-url.h \
	http-parser.h \
	http-header.h \
	http-header-parser.h \
	http-transfer.h \
	http-auth.h \
	http-message-parser.h \
	http-request.h \
	http-request-parser.h \
	http-response.h \
	http-response-parser.h \
	http-client-private.h \
	http-client.h \
	http-server-private.h \
	http-server.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs = \
	test-http-date \
	test-http-url \
	test-http-header-parser \
	test-http-transfer \
	test-http-auth \
	test-http-response-parser \
	test-http-request-parser \
	test-http-payload \
	test-http-client-errors \
	test-http-client-request \
	test-http-server-errors

test_nocheck_programs = \
	test-http-client \
	test-http-server

noinst_PROGRAMS = $(test_programs) $(test_nocheck_programs)

test_libs = \
	../lib-test/libtest.la \
	../lib/liblib.la \
	$(MODULE_LIBS)

test_deps = \
	$(noinst_LTLIBRARIES) \
	../lib-test/libtest.la \
	../lib/liblib.la

test_http_url_SOURCES = test-http-url.c
test_http_url_LDADD = http-url.lo http-header.lo $(test_libs)
test_http_url_DEPENDENCIES = $(test_deps)

test_http_date_SOURCES = test-http-date.c
test_http_date_LDADD = http-date.lo  $(test_libs)
test_http_date_DEPENDENCIES = $(test_deps)

test_http_header_parser_SOURCES = test-http-header-parser.c
test_http_header_parser_LDADD = http-parser.lo http-header-parser.lo http-header.lo $(test_libs)
test_http_header_parser_DEPENDENCIES = $(test_deps)

test_http_transfer_SOURCES = test-http-transfer.c
test_http_transfer_LDADD = \
	http-parser.lo \
	http-header-parser.lo \
	http-transfer-chunked.lo \
	http-header.lo \
	$(test_libs)
test_http_transfer_DEPENDENCIES = $(test_deps)

test_http_auth_SOURCES = test-http-auth.c
test_http_auth_LDADD = \
	http-auth.lo \
	http-parser.lo \
	$(test_libs)
test_http_auth_DEPENDENCIES = $(test_deps)

test_http_response_parser_SOURCES = test-http-response-parser.c
test_http_response_parser_LDADD = \
	http-date.lo \
	http-parser.lo \
	http-header.lo \
	http-header-parser.lo \
	http-transfer-chunked.lo \
	http-message-parser.lo \
	http-response-parser.lo \
	$(test_libs)
test_http_response_parser_DEPENDENCIES = $(test_deps)

test_http_request_parser_SOURCES = test-http-request-parser.c
test_http_request_parser_LDADD = \
	http-date.lo \
	http-parser.lo \
	http-url.lo \
	http-header.lo \
	http-header-parser.lo \
	http-transfer-chunked.lo \
	http-message-parser.lo \
	http-request-parser.lo \
	$(test_libs)
test_http_request_parser_DEPENDENCIES = $(test_deps)

test_http_libs = \
	libhttp.la \
	../lib-dns/libdns.la \
	../lib-ssl-iostream/libssl_iostream.la \
	../lib-master/libmaster.la \
	../lib-settings/libsettings.la \
	$(test_libs)
test_http_deps = \
	libhttp.la \
	../lib-dns/libdns.la \
	../lib-ssl-iostream/libssl_iostream.la \
	../lib-master/libmaster.la \
	../lib-settings/libsettings.la \
	$(test_deps)

test_http_libs_ssl=
if BUILD_OPENSSL
test_http_libs_ssl += ../lib-ssl-iostream/libssl_iostream_openssl.la
endif

test_http_payload_SOURCES = test-http-payload.c
test_http_payload_LDFLAGS = -export-dynamic
test_http_payload_LDADD = \
	$(test_http_libs) \
	$(test_http_libs_ssl)
test_http_payload_DEPENDENCIES = \
	$(test_http_deps)

test_http_client_SOURCES = test-http-client.c
test_http_client_LDFLAGS = -export-dynamic
test_http_client_LDADD = \
	$(test_http_libs) \
	$(test_http_libs_ssl)

test_http_client_DEPENDENCIES = \
	$(test_http_deps)

test_http_client_errors_SOURCES = test-http-client-errors.c
test_http_client_errors_LDFLAGS = -export-dynamic
test_http_client_errors_LDADD = \
	$(test_http_libs)
test_http_client_errors_DEPENDENCIES = \
	$(test_http_deps)

test_http_client_request_SOURCES = test-http-client-request.c
test_http_client_request_LDFLAGS = -export-dynamic
test_http_client_request_LDADD = \
	$(test_http_libs)
test_http_client_request_DEPENDENCIES = \
	$(test_http_deps)

test_http_server_SOURCES = test-http-server.c
test_http_server_LDFLAGS = -export-dynamic
test_http_server_LDADD = \
	$(test_http_libs)
test_http_server_DEPENDENCIES = \
	$(test_http_deps)

test_http_server_errors_SOURCES = test-http-server-errors.c
test_http_server_errors_LDFLAGS = -export-dynamic
test_http_server_errors_LDADD = \
	$(test_http_libs)
test_http_server_errors_DEPENDENCIES = \
	$(test_http_deps)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
