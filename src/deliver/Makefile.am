pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = deliver

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-storage \
	-DSYSCONFDIR=\""$(sysconfdir)"\"

libs = \
	../lib-storage/register/libstorage-register.a \
	$(STORAGE_LIBS) \
	../lib-storage/libstorage.a \
	../lib-storage/subscription-file/libstorage_subscription_file.a \
	../lib-imap/libimap.a \
	../lib-mail/libmail.a \
	../lib-charset/libcharset.a \
	../lib/liblib.a

deliver_LDADD = \
	$(libs) \
	$(LIBICONV) \
	$(RAND_LIBS) \
	$(MODULE_LIBS)

deliver_DEPENDENCIES = $(libs)

deliver_SOURCES = \
	deliver.c
