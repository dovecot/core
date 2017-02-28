noinst_LTLIBRARIES = liblda.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-dns \
	-I$(top_srcdir)/src/lib-smtp \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-program-client \
	-DTEST_BIN_DIR=\"$(abs_srcdir)/test-bin\"

liblda_la_SOURCES = \
	duplicate.c \
	lda-settings.c \
	mail-deliver.c \
	mail-send.c \
	smtp-client.c

headers = \
	duplicate.h \
	lda-settings.h \
	mail-deliver.h \
	mail-send.h \
	smtp-client.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

deps=../lib-storage/libdovecot-storage.la ../lib-dovecot/libdovecot.la

pkglib_LTLIBRARIES = libdovecot-lda.la
libdovecot_lda_la_SOURCES = 
libdovecot_lda_la_LIBADD = liblda.la $(deps)
libdovecot_lda_la_DEPENDENCIES = liblda.la $(deps)
libdovecot_lda_la_LDFLAGS = -export-dynamic

test_programs =

test_nocheck_programs = \
	test-smtp-client

noinst_PROGRAMS = $(test_programs) $(test_nocheck_programs)

test_libs = \
	liblda.la \
	../lib-smtp/libsmtp.la \
	../lib-program-client/libprogram_client.la \
	../lib-dns/libdns.la \
	../lib-mail/libmail.la \
	../lib-master/libmaster.la \
	../lib-ssl-iostream/libssl_iostream.la \
	../lib-settings/libsettings.la \
	../lib-test/libtest.la \
	../lib/liblib.la \
	$(MODULE_LIBS)

test_deps = \
	liblda.la \
	../lib-smtp/libsmtp.la \
	../lib-program-client/libprogram_client.la \
	../lib-dns/libdns.la \
	../lib-mail/libmail.la \
	../lib-master/libmaster.la \
	../lib-ssl-iostream/libssl_iostream.la \
	../lib-settings/libsettings.la \
	../lib-test/libtest.la \
	../lib/liblib.la

test_smtp_client_SOURCES = test-smtp-client.c
test_smtp_client_LDFLAGS = -export-dynamic
test_smtp_client_LDADD = $(test_libs)
test_smtp_client_DEPENDENCIES = $(test_deps)

check: check-am check-test
check-test: all-am
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
