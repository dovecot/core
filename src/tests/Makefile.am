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

libs = \
	libtest.a \
	$(LIBDOVECOT)

test_lib_SOURCES = \
	test-istream.c \
	test-lib.c

test_lib_LDADD = $(libs)
test_lib_DEPENDENCIES = $(libs)

test_mail_SOURCES = \
	test-mail.c

test_mail_LDADD = $(libs)
test_mail_DEPENDENCIES = $(libs)

test_imap_SOURCES = \
	test-imap.c

noinst_HEADERS = \
	test-common.h \
	test-lib.h

test_imap_LDADD = $(libs)
test_imap_DEPENDENCIES = $(libs)
