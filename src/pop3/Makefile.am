pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = pop3

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-storage

libs = \
	../lib-storage/register/libstorage-register.a \
	$(STORAGE_LIBS) \
	../lib-storage/libstorage.a \
	../lib-storage/subscription-file/libstorage_subscription_file.a \
	../lib-imap/libimap.a \
	../lib-mail/libmail.a \
	../lib-charset/libcharset.a \
	../lib/liblib.a

pop3_LDADD = \
	$(libs) \
	$(LIBICONV) \
	$(RAND_LIBS) \
	$(MODULE_LIBS)

pop3_DEPENDENCIES = $(libs)

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
