noinst_PROGRAMS = test-lib test-mail test-imap

noinst_LIBRARIES = libtest.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage

libtest_a_SOURCES = \
	test-common.c

test_lib_SOURCES = \
	test-istream.c \
	test-lib.c

test_lib_LDADD = \
	libtest.a \
	../lib-dovecot/libdovecot.la

test_mail_SOURCES = \
	test-mail.c

test_imap_SOURCES = \
	test-imap.c

noinst_HEADERS = \
	test-common.h \
	test-lib.h

test_mail_LDADD = \
	$(LIBICONV) \
	libtest.a \
	../lib-dovecot/libdovecot.la

test_imap_LDADD = \
	$(LIBICONV) \
	libtest.a \
	../lib-dovecot/libdovecot.la
