noinst_LTLIBRARIES = libmail.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-charset

libmail_la_SOURCES = \
	istream-attachment-connector.c \
	istream-attachment-extractor.c \
	istream-binary-converter.c \
	istream-dot.c \
	istream-header-filter.c \
	istream-nonuls.c \
	istream-qp-decoder.c \
	mail-user-hash.c \
	mbox-from.c \
	message-address.c \
	message-binary-part.c \
	message-date.c \
	message-decoder.c \
	message-header-decode.c \
	message-header-encode.c \
	message-header-parser.c \
	message-id.c \
	message-parser.c \
	message-part-serialize.c \
	message-search.c \
	message-size.c \
	quoted-printable.c \
	rfc2231-parser.c \
	rfc822-parser.c

headers = \
	istream-attachment-connector.h \
	istream-attachment-extractor.h \
	istream-binary-converter.h \
	istream-dot.h \
	istream-header-filter.h \
	istream-nonuls.h \
	istream-qp.h \
	mail-user-hash.h \
	mbox-from.h \
	mail-types.h \
	message-address.h \
	message-binary-part.h \
	message-date.h \
	message-decoder.h \
	message-header-decode.h \
	message-header-encode.h \
	message-header-parser.h \
	message-id.h \
	message-parser.h \
	message-part-serialize.h \
	message-search.h \
	message-size.h \
	quoted-printable.h \
	rfc2231-parser.h \
	rfc822-parser.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs = \
	test-istream-dot \
	test-istream-attachment \
	test-istream-binary-converter \
	test-istream-header-filter \
	test-istream-qp-decoder \
	test-mbox-from \
	test-message-address \
	test-message-date \
	test-message-decoder \
	test-message-header-decode \
	test-message-header-encode \
	test-message-header-parser \
	test-message-id \
	test-message-parser \
	test-quoted-printable \
	test-rfc2231-parser

noinst_PROGRAMS = $(test_programs)

test_libs = \
	../lib-test/libtest.la \
	../lib/liblib.la

test_deps = $(noinst_LTLIBRARIES) $(test_libs)

test_istream_dot_SOURCES = test-istream-dot.c
test_istream_dot_LDADD = istream-dot.lo $(test_libs)
test_istream_dot_DEPENDENCIES = $(test_deps)

test_istream_qp_decoder_SOURCES = test-istream-qp-decoder.c
test_istream_qp_decoder_LDADD = istream-qp-decoder.lo quoted-printable.lo $(test_libs)
test_istream_qp_decoder_DEPENDENCIES = $(test_deps)

message_parser_objects = \
	message-parser.lo \
	message-header-parser.lo \
	message-size.lo \
	rfc822-parser.lo \
	rfc2231-parser.lo

test_istream_binary_converter_SOURCES = test-istream-binary-converter.c
test_istream_binary_converter_LDADD = istream-binary-converter.lo $(message_parser_objects)  $(test_libs)
test_istream_binary_converter_DEPENDENCIES = $(test_deps)

test_istream_attachment_SOURCES = test-istream-attachment.c
test_istream_attachment_LDADD = istream-attachment-extractor.lo istream-attachment-connector.lo $(message_parser_objects) $(test_libs)
test_istream_attachment_DEPENDENCIES = $(test_deps)

test_istream_header_filter_SOURCES = test-istream-header-filter.c
test_istream_header_filter_LDADD = istream-header-filter.lo message-header-parser.lo $(test_libs)
test_istream_header_filter_DEPENDENCIES = $(test_deps)

test_mbox_from_SOURCES = test-mbox-from.c
test_mbox_from_LDADD = mbox-from.lo $(test_libs)
test_mbox_from_DEPENDENCIES = $(test_deps)

test_message_address_SOURCES = test-message-address.c
test_message_address_LDADD = message-address.lo rfc822-parser.lo $(test_libs)
test_message_address_DEPENDENCIES = $(test_deps)

test_message_date_SOURCES = test-message-date.c
test_message_date_LDADD = message-date.lo rfc822-parser.lo $(test_libs)
test_message_date_DEPENDENCIES = $(test_deps)

test_message_decoder_SOURCES = test-message-decoder.c
test_message_decoder_LDADD = message-decoder.lo rfc822-parser.lo rfc2231-parser.lo $(test_libs)
test_message_decoder_DEPENDENCIES = $(test_deps)

test_message_header_decode_SOURCES = test-message-header-decode.c
test_message_header_decode_LDADD = message-header-decode.lo quoted-printable.lo $(test_libs)
test_message_header_decode_DEPENDENCIES = $(test_deps)

test_message_header_encode_SOURCES = test-message-header-encode.c
test_message_header_encode_LDADD = message-header-encode.lo $(test_libs)
test_message_header_encode_DEPENDENCIES = $(test_deps)

test_message_header_parser_SOURCES = test-message-header-parser.c
test_message_header_parser_LDADD = message-header-parser.lo $(test_libs)
test_message_header_parser_DEPENDENCIES = $(test_deps)

test_message_id_SOURCES = test-message-id.c
test_message_id_LDADD = message-id.lo rfc822-parser.lo $(test_libs)
test_message_id_DEPENDENCIES = $(test_deps)

test_message_parser_SOURCES = test-message-parser.c
test_message_parser_LDADD = message-parser.lo message-header-parser.lo message-size.lo rfc822-parser.lo rfc2231-parser.lo $(test_libs)
test_message_parser_DEPENDENCIES = $(test_deps)

test_quoted_printable_SOURCES = test-quoted-printable.c
test_quoted_printable_LDADD = quoted-printable.lo $(test_libs)
test_quoted_printable_DEPENDENCIES = $(test_deps)

test_rfc2231_parser_SOURCES = test-rfc2231-parser.c
test_rfc2231_parser_LDADD = rfc2231-parser.lo rfc822-parser.lo $(test_libs)
test_rfc2231_parser_DEPENDENCIES = $(test_deps)

check: check-am check-test
check-test: all-am
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
