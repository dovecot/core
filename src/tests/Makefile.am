noinst_PROGRAMS = test-lib test-mail

noinst_LIBRARIES = libtest.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage

libtest_a_SOURCES = \
	test-common.c

test_lib_SOURCES = \
	test-lib.c

test_lib_LDADD = \
	libtest.a \
	../lib/liblib.a

test_mail_SOURCES = \
	test-mail.c

test_mail_LDADD = \
	libtest.a \
	../lib-mail/libmail.a \
	../lib-charset/libcharset.a \
	../lib/liblib.a
