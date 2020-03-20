noinst_LTLIBRARIES = libsmtp.la

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-sasl \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-dns \
	-I$(top_srcdir)/src/lib-program-client \
	-I$(top_srcdir)/src/lib-mail \
	-DTEST_BIN_DIR=\"$(abs_srcdir)/test-bin\"

smtp_server_cmds = \
	smtp-server-cmd-helo.c \
	smtp-server-cmd-starttls.c \
	smtp-server-cmd-auth.c \
	smtp-server-cmd-mail.c \
	smtp-server-cmd-rcpt.c \
	smtp-server-cmd-data.c \
	smtp-server-cmd-rset.c \
	smtp-server-cmd-noop.c \
	smtp-server-cmd-quit.c \
	smtp-server-cmd-vrfy.c \
	smtp-server-cmd-xclient.c

libsmtp_la_SOURCES = \
	smtp-parser.c \
	smtp-syntax.c \
	smtp-address.c \
	smtp-common.c \
	smtp-params.c \
	smtp-reply.c \
	smtp-reply-parser.c \
	smtp-command-parser.c \
	smtp-client-command.c \
	smtp-client-transaction.c \
	smtp-client-connection.c \
	smtp-client.c \
	$(smtp_server_cmds) \
	smtp-server-reply.c \
	smtp-server-command.c \
	smtp-server-recipient.c \
	smtp-server-transaction.c \
	smtp-server-connection.c \
	smtp-server.c \
	smtp-submit-settings.c \
	smtp-submit.c

headers = \
	smtp-parser.h \
	smtp-syntax.h \
	smtp-address.h \
	smtp-common.h \
	smtp-params.h \
	smtp-reply.h \
	smtp-reply-parser.h \
	smtp-command.h \
	smtp-command-parser.h \
	smtp-client-command.h \
	smtp-client-transaction.h \
	smtp-client-connection.h \
	smtp-client-private.h \
	smtp-client.h \
	smtp-server-private.h \
	smtp-server.h \
	smtp-submit-settings.h \
	smtp-submit.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs = \
	test-smtp-syntax \
	test-smtp-address \
	test-smtp-params \
	test-smtp-reply \
	test-smtp-command-parser \
	test-smtp-payload \
	test-smtp-submit \
	test-smtp-client-errors \
	test-smtp-server-errors

test_nocheck_programs =

fuzz_programs =

if USE_FUZZER
fuzz_programs += \
	fuzz-smtp-server
endif

noinst_PROGRAMS = $(fuzz_programs) $(test_programs) $(test_nocheck_programs)

EXTRA_DIST = \
	test-bin/sendmail-exit-1.sh \
	test-bin/sendmail-success.sh

test_libs = \
	$(noinst_LTLIBRARIES) \
	../lib-program-client/libprogram_client.la \
	../lib-dns/libdns.la \
	../lib-mail/libmail.la \
	../lib-charset/libcharset.la \
	../lib-master/libmaster.la \
	../lib-auth/libauth.la \
	../lib-ssl-iostream/libssl_iostream.la \
	../lib-settings/libsettings.la \
	../lib-sasl/libsasl.la \
	../lib-test/libtest.la \
	../lib/liblib.la \
	$(MODULE_LIBS)

test_deps = \
	$(noinst_LTLIBRARIES) \
	../lib-program-client/libprogram_client.la \
	../lib-dns/libdns.la \
	../lib-mail/libmail.la \
	../lib-charset/libcharset.la \
	../lib-master/libmaster.la \
	../lib-auth/libauth.la \
	../lib-ssl-iostream/libssl_iostream.la \
	../lib-settings/libsettings.la \
	../lib-sasl/libsasl.la \
	../lib-test/libtest.la \
	../lib/liblib.la

test_libs_ssl=
if BUILD_OPENSSL
test_libs_ssl += ../lib-ssl-iostream/libssl_iostream_openssl.la
endif

test_smtp_syntax_SOURCES = test-smtp-syntax.c
test_smtp_syntax_LDADD = $(test_libs)
test_smtp_syntax_DEPENDENCIES = $(test_deps)

test_smtp_address_SOURCES = test-smtp-address.c
test_smtp_address_LDFLAGS = -export-dynamic
test_smtp_address_LDADD = $(test_libs)
test_smtp_address_DEPENDENCIES = $(test_deps)

test_smtp_params_SOURCES = test-smtp-params.c
test_smtp_params_LDFLAGS = -export-dynamic
test_smtp_params_LDADD = $(test_libs)
test_smtp_params_DEPENDENCIES = $(test_deps)

test_smtp_reply_SOURCES = test-smtp-reply.c
test_smtp_reply_LDFLAGS = -export-dynamic
test_smtp_reply_LDADD = $(test_libs)
test_smtp_reply_DEPENDENCIES = $(test_deps)

test_smtp_command_parser_SOURCES = test-smtp-command-parser.c
test_smtp_command_parser_LDFLAGS = -export-dynamic
test_smtp_command_parser_LDADD = $(test_libs)
test_smtp_command_parser_DEPENDENCIES = $(test_deps)

test_smtp_payload_SOURCES = test-smtp-payload.c
test_smtp_payload_LDFLAGS = -export-dynamic
test_smtp_payload_LDADD = $(test_libs) $(test_libs_ssl)
test_smtp_payload_DEPENDENCIES = $(test_deps)

test_smtp_submit_SOURCES = test-smtp-submit.c
test_smtp_submit_LDFLAGS = -export-dynamic
test_smtp_submit_LDADD = $(test_libs)
test_smtp_submit_DEPENDENCIES = $(test_deps)

test_smtp_client_errors_SOURCES = test-smtp-client-errors.c
test_smtp_client_errors_LDFLAGS = -export-dynamic
test_smtp_client_errors_LDADD = $(test_libs)
test_smtp_client_errors_DEPENDENCIES = $(test_deps)

test_smtp_server_errors_SOURCES = test-smtp-server-errors.c
test_smtp_server_errors_LDFLAGS = -export-dynamic
test_smtp_server_errors_LDADD = $(test_libs)
test_smtp_server_errors_DEPENDENCIES = $(test_deps)

nodist_EXTRA_fuzz_smtp_server_SOURCES = force-cxx-linking.cxx
fuzz_smtp_server_CPPFLAGS = $(FUZZER_CPPFLAGS)
fuzz_smtp_server_LDFLAGS = $(FUZZER_LDFLAGS)
fuzz_smtp_server_SOURCES = fuzz-smtp-server.c
fuzz_smtp_server_LDADD = $(test_libs)
fuzz_smtp_server_DEPENDENCIES = $(test_deps)

check-local:
	for bin in $(test_programs); do \
	  if test "$$bin" = "test-smtp-submit"; then \
	    if ! env NOCHILDREN=yes $(RUN_TEST) ./$$bin; then exit 1; fi; \
          else \
	    if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	  fi \
	done
