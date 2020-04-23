noinst_LTLIBRARIES = libmail.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-charset \
	-I$(top_srcdir)/src/lib-smtp

libmail_la_SOURCES = \
	istream-attachment-connector.c \
	istream-attachment-extractor.c \
	istream-binary-converter.c \
	istream-dot.c \
	istream-header-filter.c \
	istream-nonuls.c \
	istream-qp-decoder.c \
	istream-qp-encoder.c \
	mail-html2text.c \
	mail-user-hash.c \
	mbox-from.c \
	message-address.c \
	message-binary-part.c \
	message-date.c \
	message-decoder.c \
	message-header-decode.c \
	message-header-encode.c \
	message-header-hash.c \
	message-header-parser.c \
	message-id.c \
	message-parser.c \
	message-parser-from-parts.c \
	message-part.c \
	message-part-data.c \
	message-part-serialize.c \
	message-search.c \
	message-size.c \
	message-snippet.c \
	ostream-dot.c \
	qp-decoder.c \
	qp-encoder.c \
	quoted-printable.c \
	rfc2231-parser.c \
	rfc822-parser.c

noinst_HEADERS = \
	html-entities.h \
	message-parser-private.h

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
	mail-html2text.h \
	mail-types.h \
	message-address.h \
	message-binary-part.h \
	message-date.h \
	message-decoder.h \
	message-header-decode.h \
	message-header-encode.h \
	message-header-hash.h \
	message-header-parser.h \
	message-id.h \
	message-parser.h \
	message-part.h \
	message-part-data.h \
	message-part-serialize.h \
	message-search.h \
	message-size.h \
	message-snippet.h \
	ostream-dot.h \
	qp-decoder.h \
	qp-encoder.h \
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
	test-istream-qp-encoder \
	test-mail-html2text \
	test-mbox-from \
	test-message-address \
	test-message-date \
	test-message-decoder \
	test-message-header-decode \
	test-message-header-encode \
	test-message-header-hash \
	test-message-header-parser \
	test-message-id \
	test-message-parser \
	test-message-part \
	test-message-search \
	test-message-snippet \
	test-ostream-dot \
	test-qp-decoder \
	test-qp-encoder \
	test-quoted-printable \
	test-rfc2231-parser \
	test-rfc822-parser

noinst_PROGRAMS = $(test_programs)

test_libs = \
	$(noinst_LTLIBRARIES) \
	../lib-test/libtest.la \
	../lib/liblib.la

test_deps = $(noinst_LTLIBRARIES) $(test_libs)

test_istream_dot_SOURCES = test-istream-dot.c
test_istream_dot_LDADD = $(test_libs)
test_istream_dot_DEPENDENCIES = $(test_deps)

test_istream_qp_decoder_SOURCES = test-istream-qp-decoder.c
test_istream_qp_decoder_LDADD = $(test_libs)
test_istream_qp_decoder_DEPENDENCIES = $(test_deps)

test_istream_qp_encoder_SOURCES = test-istream-qp-encoder.c
test_istream_qp_encoder_LDADD = $(test_libs)
test_istream_qp_encoder_DEPENDENCIES = $(test_deps)

test_istream_binary_converter_SOURCES = test-istream-binary-converter.c
test_istream_binary_converter_LDADD = $(test_libs)
test_istream_binary_converter_DEPENDENCIES = $(test_deps)

test_istream_attachment_SOURCES = test-istream-attachment.c
test_istream_attachment_LDADD = $(test_libs)
test_istream_attachment_DEPENDENCIES = $(test_deps)

test_istream_header_filter_SOURCES = test-istream-header-filter.c
test_istream_header_filter_LDADD = $(test_libs)
test_istream_header_filter_DEPENDENCIES = $(test_deps)

test_mbox_from_SOURCES = test-mbox-from.c
test_mbox_from_LDADD = $(test_libs)
test_mbox_from_DEPENDENCIES = $(test_deps)

test_message_address_SOURCES = test-message-address.c
test_message_address_LDADD = $(test_libs)
test_message_address_DEPENDENCIES = $(test_deps)

test_message_date_SOURCES = test-message-date.c
test_message_date_LDADD = $(test_libs)
test_message_date_DEPENDENCIES = $(test_deps)

test_message_decoder_SOURCES = test-message-decoder.c
test_message_decoder_LDADD = $(test_libs) ../lib-charset/libcharset.la
test_message_decoder_DEPENDENCIES = $(test_deps) ../lib-charset/libcharset.la

test_message_header_decode_SOURCES = test-message-header-decode.c
test_message_header_decode_LDADD = $(test_libs)
test_message_header_decode_DEPENDENCIES = $(test_deps)

test_message_header_encode_SOURCES = test-message-header-encode.c
test_message_header_encode_LDADD = $(test_libs)
test_message_header_encode_DEPENDENCIES = $(test_deps)

test_message_header_hash_SOURCES = test-message-header-hash.c
test_message_header_hash_LDADD = $(test_libs)
test_message_header_hash_DEPENDENCIES = $(test_deps)

test_message_header_parser_SOURCES = test-message-header-parser.c
test_message_header_parser_LDADD = $(test_libs)
test_message_header_parser_DEPENDENCIES = $(test_deps)

test_message_id_SOURCES = test-message-id.c
test_message_id_LDADD = $(test_libs)
test_message_id_DEPENDENCIES = $(test_deps)

test_message_parser_SOURCES = test-message-parser.c
test_message_parser_LDADD = $(test_libs)
test_message_parser_DEPENDENCIES = $(test_deps)

test_message_part_SOURCES = test-message-part.c
test_message_part_LDADD = $(test_libs)
test_message_part_DEPENDENCIES = $(test_deps)

test_message_search_SOURCES = test-message-search.c
test_message_search_LDADD = $(test_libs) ../lib-charset/libcharset.la
test_message_search_DEPENDENCIES = $(test_deps) ../lib-charset/libcharset.la

test_message_snippet_SOURCES = test-message-snippet.c
test_message_snippet_LDADD = $(test_message_decoder_LDADD)
test_message_snippet_DEPENDENCIES = $(test_deps)

test_mail_html2text_SOURCES = test-mail-html2text.c
test_mail_html2text_LDADD = $(test_libs)
test_mail_html2text_DEPENDENCIES = $(test_deps)

test_ostream_dot_SOURCES = test-ostream-dot.c
test_ostream_dot_LDADD = $(test_libs)
test_ostream_dot_DEPENDENCIES = $(test_deps)

test_qp_decoder_SOURCES = test-qp-decoder.c
test_qp_decoder_LDADD = $(test_libs)
test_qp_decoder_DEPENDENCIES = $(test_deps)

test_qp_encoder_SOURCES = test-qp-encoder.c
test_qp_encoder_LDADD = $(test_libs)
test_qp_encoder_DEPENDENCIES = $(test_deps)

test_quoted_printable_SOURCES = test-quoted-printable.c
test_quoted_printable_LDADD = $(test_libs)
test_quoted_printable_DEPENDENCIES = $(test_deps)

test_rfc2231_parser_SOURCES = test-rfc2231-parser.c
test_rfc2231_parser_LDADD = $(test_libs)
test_rfc2231_parser_DEPENDENCIES = $(test_deps)

test_rfc822_parser_SOURCES = test-rfc822-parser.c
test_rfc822_parser_LDADD = $(test_libs)
test_rfc822_parser_DEPENDENCIES = $(test_deps)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
