noinst_LTLIBRARIES = libstorage_shared.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index

libstorage_shared_la_SOURCES = \
	shared-list.c \
	shared-storage.c

headers = \
	shared-storage.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
