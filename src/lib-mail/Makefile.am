noinst_LIBRARIES = libmail.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-charset

libmail_a_SOURCES = \
	istream-header-filter.c \
	message-address.c \
	message-body-search.c \
	message-content-parser.c \
	message-date.c \
	message-decoder.c \
	message-header-decode.c \
	message-header-parser.c \
	message-header-search.c \
	message-id.c \
	message-parser.c \
	message-part-serialize.c \
	message-send.c \
	message-size.c \
	quoted-printable.c \
	rfc822-parser.c

headers = \
	istream-header-filter.h \
	mail-types.h \
	message-address.h \
	message-body-search.h \
	message-content-parser.h \
	message-date.h \
	message-decoder.h \
	message-header-decode.h \
	message-header-parser.h \
	message-header-search.h \
	message-id.h \
	message-parser.h \
	message-part-serialize.h \
	message-send.h \
	message-size.h \
	quoted-printable.h \
	rfc822-parser.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)/src/lib-mail
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif
