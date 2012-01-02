noinst_LTLIBRARIES = libstorage_pop3c.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-dns \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index

libstorage_pop3c_la_SOURCES = \
	pop3c-client.c \
	pop3c-mail.c \
	pop3c-settings.c \
	pop3c-storage.c \
	pop3c-sync.c

headers = \
	pop3c-client.h \
	pop3c-settings.h \
	pop3c-storage.h \
	pop3c-sync.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
