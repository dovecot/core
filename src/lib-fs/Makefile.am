noinst_LTLIBRARIES = libfs.la

noinst_PROGRAMS = fs-test

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

fs_test_SOURCES = fs-test.c
fs_test_LDFLAGS = -export-dynamic
fs_test_DEPENDENCIES = \
	libfs.la \
	../lib-http/libhttp.la \
	../lib-ssl-iostream/libssl_iostream.la \
	../lib-dns/libdns.la \
	../lib/liblib.la
fs_test_LDADD = $(fs_test_DEPENDENCIES) $(MODULE_LIBS)

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
