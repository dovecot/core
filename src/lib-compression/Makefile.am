noinst_LTLIBRARIES = libcompression.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test

libcompression_la_SOURCES = \
	compression.c \
	istream-zlib.c \
	istream-bzlib.c \
	ostream-zlib.c \
	ostream-bzlib.c
libcompression_la_LIBADD = \
	$(COMPRESS_LIBS)

pkginc_libdir = $(pkgincludedir)
pkginc_lib_HEADERS = \
	compression.h \
	istream-zlib.h \
	ostream-zlib.h

pkglib_LTLIBRARIES = libdovecot-compression.la
libdovecot_compression_la_SOURCES = 
libdovecot_compression_la_LIBADD = libcompression.la ../lib/liblib.la $(COMPRESS_LIBS)
libdovecot_compression_la_DEPENDENCIES = libcompression.la
libdovecot_compression_la_LDFLAGS = -export-dynamic
