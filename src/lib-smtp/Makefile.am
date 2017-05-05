noinst_LTLIBRARIES = libsmtp.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-dns \
	-I$(top_srcdir)/src/lib-program-client \
	-I$(top_srcdir)/src/lib-mail \
	-DTEST_BIN_DIR=\"$(abs_srcdir)/test-bin\"

libsmtp_la_SOURCES = \
	lmtp-client.c \
	smtp-submit.c

headers = \
	lmtp-client.h \
	smtp-submit.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs =

test_nocheck_programs = \
	test-smtp-submit

noinst_PROGRAMS = $(test_programs) $(test_nocheck_programs)

test_libs = \
	libsmtp.la \
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
	libsmtp.la \
	../lib-program-client/libprogram_client.la \
	../lib-dns/libdns.la \
	../lib-mail/libmail.la \
	../lib-master/libmaster.la \
	../lib-ssl-iostream/libssl_iostream.la \
	../lib-settings/libsettings.la \
	../lib-test/libtest.la \
	../lib/liblib.la

test_smtp_submit_SOURCES = test-smtp-submit.c
test_smtp_submit_LDFLAGS = -export-dynamic
test_smtp_submit_LDADD = $(test_libs)
test_smtp_submit_DEPENDENCIES = $(test_deps)

check: check-am check-test
check-test: all-am
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done

