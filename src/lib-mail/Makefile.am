noinst_LTLIBRARIES = libmail.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-charset

libmail_la_SOURCES = \
	istream-header-filter.c \
	mbox-from.c \
	message-address.c \
	message-date.c \
	message-decoder.c \
	message-header-decode.c \
	message-header-parser.c \
	message-id.c \
	message-parser.c \
	message-part-serialize.c \
	message-search.c \
	message-send.c \
	message-size.c \
	quoted-printable.c \
	rfc2231-parser.c \
	rfc822-parser.c

headers = \
	istream-header-filter.h \
	mbox-from.h \
	mail-types.h \
	message-address.h \
	message-date.h \
	message-decoder.h \
	message-header-decode.h \
	message-header-parser.h \
	message-id.h \
	message-parser.h \
	message-part-serialize.h \
	message-search.h \
	message-send.h \
	message-size.h \
	quoted-printable.h \
	rfc2231-parser.h \
	rfc822-parser.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif

test_programs = test-mail
noinst_PROGRAMS = $(test_programs)

test_libs = \
	libmail.la \
	../lib-charset/libcharset.la \
	../lib-test/libtest.la \
	../lib/liblib.la

test_mail_SOURCES = \
	test-mail.c

test_mail_LDADD = $(test_libs) $(LTLIBICONV)
test_mail_DEPENDENCIES = $(test_libs)

check: check-am check-test
check-test: $(test_programs)
	for bin in $(test_programs); do \
	  if ! ./$$bin; then exit 1; fi \
	done
