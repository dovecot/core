noinst_LTLIBRARIES = libfs.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-DMODULE_DIR=\""$(moduledir)"\"

libfs_la_SOURCES = \
	fs-api.c \
	fs-metawrap.c \
	fs-posix.c \
	fs-sis.c \
	fs-sis-common.c \
	fs-sis-queue.c \
	istream-metawrap.c \
	ostream-metawrap.c \
	ostream-cmp.c

headers = \
	fs-api.h \
	fs-api-private.h \
	fs-sis-common.h \
	istream-metawrap.h \
	ostream-metawrap.h \
	ostream-cmp.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
