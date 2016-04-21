noinst_LTLIBRARIES = libfs.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-DMODULE_DIR=\""$(moduledir)"\"

libfs_la_SOURCES = \
	fs-api.c \
	fs-dict.c \
	fs-metawrap.c \
	fs-randomfail.c \
	fs-posix.c \
	fs-test.c \
	fs-sis.c \
	fs-sis-common.c \
	fs-sis-queue.c \
	istream-fs-file.c \
	istream-fs-stats.c \
	istream-metawrap.c \
	ostream-metawrap.c \
	ostream-cmp.c

headers = \
	fs-api.h \
	fs-api-private.h \
	fs-sis-common.h \
	fs-test.h \
	istream-fs-file.h \
	istream-fs-stats.h \
	istream-metawrap.h \
	ostream-metawrap.h \
	ostream-cmp.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
