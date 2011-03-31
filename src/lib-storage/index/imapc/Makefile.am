noinst_LTLIBRARIES = libstorage_imapc.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-dns \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/list \
	-I$(top_srcdir)/src/lib-storage/index

libstorage_imapc_la_SOURCES = \
	imapc-client.c \
	imapc-connection.c \
	imapc-list.c \
	imapc-mail.c \
	imapc-mail-fetch.c \
	imapc-mailbox.c \
	imapc-save.c \
	imapc-seqmap.c \
	imapc-settings.c \
	imapc-sync.c \
	imapc-storage.c

headers = \
	imapc-client.h \
	imapc-client-private.h \
	imapc-connection.h \
	imapc-list.h \
	imapc-mail.h \
	imapc-seqmap.h \
	imapc-settings.h \
	imapc-storage.h \
	imapc-sync.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs = \
	test-imapc-seqmap

noinst_PROGRAMS = $(test_programs)

test_libs = \
	../../../lib-test/libtest.la \
	../../../lib/liblib.la

test_imapc_seqmap_SOURCES = test-imapc-seqmap.c
test_imapc_seqmap_LDADD = imapc-seqmap.lo $(test_libs)
test_imapc_seqmap_DEPENDENCIES = imapc-seqmap.lo $(test_libs)

check: check-am check-test
check-test: all-am
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
