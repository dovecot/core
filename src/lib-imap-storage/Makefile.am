include $(top_srcdir)/Makefile.test.include

noinst_LTLIBRARIES = libimap-storage.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-charset \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-imap

libimap_storage_la_SOURCES = \
	imap-msgpart.c \
	imap-msgpart-url.c \
	imap-metadata.c

headers = \
	imap-msgpart.h \
	imap-msgpart-url.h \
	imap-metadata.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs = \
	test-imap-msgpart \
	test-imap-metadata

test_imap_msgpart_SOURCES = test-imap-msgpart.c
test_imap_msgpart_LDADD = \
	libimap-storage.la \
	../lib-storage/libstorage.la \
	../lib-dovecot/libdovecot.la \
	$(LIBDOVECOT_TEST_LIBS)

test_imap_metadata_SOURCES = test-imap-metadata.c
test_imap_metadata_LDADD = \
	libimap-storage.la \
	../lib-storage/libstorage.la \
	../lib-dovecot/libdovecot.la \
	$(LIBDOVECOT_TEST_LIBS)
