include $(top_srcdir)/Makefile.test.include

pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = imap-hibernate

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-var-expand \
	$(BINARY_CFLAGS)

imap_hibernate_LDADD = $(LIBDOVECOT) \
	$(BINARY_LDFLAGS)

imap_hibernate_DEPENDENCIES = $(LIBDOVECOT_DEPS)

imap_hibernate_SOURCES = \
	imap-client.c \
	imap-client-input.c \
	imap-hibernate-client.c \
	imap-hibernate-settings.c \
	imap-master-connection.c \
	main.c

noinst_HEADERS = \
	imap-client.h \
	imap-client-input.h \
	imap-hibernate-client.h \
	imap-master-connection.h

test_programs = \
	test-imap-client-input

test_libs = \
	../lib-imap/libimap.la \
	../lib-test/libtest.la \
	../lib/liblib.la

test_imap_client_input_SOURCES = test-imap-client-input.c
test_imap_client_input_LDADD = imap-client-input.o $(test_libs)
test_imap_client_input_DEPENDENCIES = $(pkglibexec_PROGRAMS) $(test_libs)
