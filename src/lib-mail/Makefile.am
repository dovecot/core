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
	message-header-decode.c \
	message-header-search.c \
	message-parser.c \
	message-part-serialize.c \
	message-send.c \
	message-size.c \
	message-tokenize.c \
	quoted-printable.c \
	rfc822-parser.c

noinst_HEADERS = \
	istream-header-filter.h \
	mail-types.h \
	message-address.h \
	message-body-search.h \
	message-content-parser.h \
	message-date.h \
	message-header-decode.h \
	message-header-search.h \
	message-parser.h \
	message-part-serialize.h \
	message-send.h \
	message-size.h \
	message-tokenize.h \
	quoted-printable.h \
	rfc822-parser.h
