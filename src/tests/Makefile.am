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
	test-istream.c \
	test-lib.c

test_lib_LDADD = \
	$(RAND_LIBS) \
	libtest.a \
	../lib/liblib.a

test_mail_SOURCES = \
	test-mail.c

noinst_HEADERS = \
	test-common.h \
	test-lib.h

test_mail_LDADD = \
	$(LIBICONV) \
	$(RAND_LIBS) \
	libtest.a \
	../lib-mail/libmail.a \
	../lib-charset/libcharset.a \
	../lib/liblib.a
