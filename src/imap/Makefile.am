pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = imap

INCLUDES = \
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

imap_LDADD = \
	$(libs) \
	$(LIBICONV) \
	$(RAND_LIBS) \
	$(MODULE_LIBS)

imap_DEPENDENCIES = $(libs)

cmds = \
	cmd-append.c \
	cmd-authenticate.c \
	cmd-capability.c \
	cmd-check.c \
	cmd-close.c \
	cmd-copy.c \
	cmd-create.c \
	cmd-delete.c \
	cmd-examine.c \
	cmd-expunge.c \
	cmd-fetch.c \
	cmd-idle.c \
	cmd-list.c \
	cmd-login.c \
	cmd-logout.c \
	cmd-lsub.c \
	cmd-namespace.c \
	cmd-noop.c \
	cmd-rename.c \
	cmd-search.c \
	cmd-select.c \
	cmd-sort.c \
	cmd-status.c \
	cmd-store.c \
	cmd-subscribe.c \
	cmd-thread.c \
	cmd-uid.c \
	cmd-unselect.c \
	cmd-unsubscribe.c

imap_SOURCES = \
	$(cmds) \
	client.c \
	commands.c \
	commands-util.c \
	imap-expunge.c \
	imap-fetch.c \
	imap-fetch-body-section.c \
	imap-search.c \
	imap-sort.c \
	imap-thread.c \
	mail-storage-callbacks.c \
	main.c \
	namespace.c


noinst_HEADERS = \
	client.h \
	commands.h \
	commands-util.h \
	common.h \
	imap-expunge.h \
	imap-fetch.h \
	imap-search.h \
	imap-sort.h \
	imap-thread.h \
	namespace.h
