noinst_LTLIBRARIES = libhttp.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-dns \
	-I$(top_srcdir)/src/lib-ssl-iostream

libhttp_la_SOURCES = \
	http-date.c \
	http-url.c \
	http-parser.c \
	http-header-parser.c \
	http-transfer-chunked.c \
	http-message-parser.c \
	http-request-parser.c \
	http-response-parser.c \
	http-client-request.c \
	http-client-connection.c \
	http-client-peer.c \
	http-client-host.c \
	http-client.c

headers = \
	http-date.h \
	http-url.h \
	http-parser.h \
	http-header-parser.h \
	http-transfer.h \
	http-message-parser.h \
	http-request-parser.h \
	http-response.h \
	http-response-parser.h \
	http-client-private.h \
	http-client.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs = \
	test-http-date \
	test-http-url \
	test-http-header-parser \
	test-http-transfer \
	test-http-response-parser

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
test_http_url_LDADD = http-url.lo  $(test_libs)
test_http_url_DEPENDENCIES = $(test_deps)

test_http_date_SOURCES = test-http-date.c
test_http_date_LDADD = http-date.lo  $(test_libs)
test_http_date_DEPENDENCIES = $(test_deps)

test_http_header_parser_SOURCES = test-http-header-parser.c
test_http_header_parser_LDADD = http-parser.lo http-header-parser.lo $(test_libs)
test_http_header_parser_DEPENDENCIES = $(test_deps)

test_http_transfer_SOURCES = test-http-transfer.c
test_http_transfer_LDADD = \
	http-parser.lo \
	http-header-parser.lo \
	http-transfer-chunked.lo \
	$(test_libs)
test_http_transfer_DEPENDENCIES = $(test_deps)

test_http_response_parser_SOURCES = test-http-response-parser.c
test_http_response_parser_LDADD = \
	http-date.lo \
	http-parser.lo \
	http-header-parser.lo \
	http-transfer-chunked.lo \
	http-message-parser.lo \
	http-response-parser.lo \
	$(test_libs)
test_http_response_parser_DEPENDENCIES = $(test_deps)

test_http_client_SOURCES = test-http-client.c
test_http_client_LDFLAGS = -export-dynamic
test_http_client_LDADD = \
	libhttp.la \
	../lib-dns/libdns.la \
	../lib-ssl-iostream/libssl_iostream.la \
	$(test_libs)
test_http_client_DEPENDENCIES = \
	libhttp.la \
	../lib-dns/libdns.la \
	../lib-ssl-iostream/libssl_iostream.la \
	$(test_deps)

test_http_server_SOURCES = test-http-server.c
test_http_server_LDFLAGS = -export-dynamic
test_http_server_LDADD = \
	libhttp.la \
	../lib-dns/libdns.la \
	../lib-ssl-iostream/libssl_iostream.la \
	$(test_libs)
test_http_server_DEPENDENCIES = \
	libhttp.la \
	../lib-dns/libdns.la \
	../lib-ssl-iostream/libssl_iostream.la \
	$(test_deps)

check: check-am check-test
check-test: all-am
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
