noinst_LTLIBRARIES = libimap.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-charset \
	-I$(top_srcdir)/src/lib-mail

libimap_la_SOURCES = \
	imap-base-subject.c \
	imap-bodystructure.c \
	imap-date.c \
	imap-envelope.c \
	imap-id.c \
	imap-match.c \
	imap-parser.c \
	imap-quote.c \
	imap-seqset.c \
	imap-utf7.c \
	imap-util.c

headers = \
	imap-base-subject.h \
	imap-bodystructure.h \
	imap-date.h \
	imap-envelope.h \
	imap-id.h \
	imap-match.h \
	imap-parser.h \
	imap-resp-code.h \
	imap-quote.h \
	imap-seqset.h \
	imap-utf7.h \
	imap-util.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)/src/lib-imap
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif
