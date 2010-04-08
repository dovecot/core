noinst_LTLIBRARIES = libstorage_cydir.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index

libstorage_cydir_la_SOURCES = \
	cydir-mail.c \
	cydir-save.c \
	cydir-sync.c \
	cydir-storage.c

headers = \
	cydir-storage.h \
	cydir-sync.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
