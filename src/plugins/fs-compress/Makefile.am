fs_moduledir = $(moduledir)
fs_module_LTLIBRARIES = \
	libfs_compress.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-compression \
	-I$(top_srcdir)/src/lib-fs

NOPLUGIN_LDFLAGS =
libfs_compress_la_SOURCES = fs-compress.c
libfs_compress_la_LIBADD = ../../lib-compression/libdovecot-compression.la
libfs_compress_la_DEPENDENCIES = ../../lib-compression/libdovecot-compression.la
libfs_compress_la_LDFLAGS = -module -avoid-version
