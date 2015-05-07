noinst_LTLIBRARIES = libfs.la

fs_moduledir = $(moduledir)
fs_module_LTLIBRARIES = \
	libfs_compress.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-compression \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-DMODULE_DIR=\""$(moduledir)"\"

libfs_la_SOURCES = \
	fs-api.c \
	fs-metawrap.c \
	fs-posix.c \
	fs-sis.c \
	fs-sis-common.c \
	fs-sis-queue.c \
	istream-fs-file.c \
	istream-metawrap.c \
	ostream-metawrap.c \
	ostream-cmp.c

libfs_compress_la_SOURCES = fs-compress.c
libfs_compress_la_LIBADD = ../lib-compression/libdovecot-compression.la
libfs_compress_la_DEPS = ../lib-compression/libdovecot-compression.la
libfs_compress_la_LDFLAGS = -module -avoid-version

headers = \
	fs-api.h \
	fs-api-private.h \
	fs-sis-common.h \
	istream-fs-file.h \
	istream-metawrap.h \
	ostream-metawrap.h \
	ostream-cmp.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
