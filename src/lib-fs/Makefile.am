noinst_LTLIBRARIES = libfs.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib

libfs_la_SOURCES = \
	fs-api.c \
	fs-posix.c \
	fs-sis.c \
	fs-sis-common.c \
	fs-sis-queue.c \
	ostream-cmp.c

headers = \
	fs-api.h \
	fs-api-private.h \
	fs-sis-common.h \
	ostream-cmp.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
