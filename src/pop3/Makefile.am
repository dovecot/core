pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = pop3

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-storage

pop3_LDADD = \
	../lib-storage/register/libstorage-register.a \
	../lib-storage/index/maildir/libstorage_maildir.a \
	../lib-storage/index/mbox/libstorage_mbox.a \
	../lib-storage/index/libstorage_index.a \
	../lib-storage/libstorage.a \
	../lib-index/maildir/libstorage_index_maildir.a \
	../lib-index/mbox/libstorage_index_mbox.a \
	../lib-index/libstorage_index.a \
	../lib-storage/subscription-file/libstorage_subscription_file.a \
	../lib-imap/libimap.a \
	../lib-mail/libmail.a \
	../lib-charset/libcharset.a \
	../lib/liblib.a \
	@LTLIBICONV@

pop3_SOURCES = \
	client.c \
	commands.c \
	mail-storage-callbacks.c \
	main.c

noinst_HEADERS = \
	capability.h \
	client.h \
	commands.h \
	common.h
