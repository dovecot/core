pkglib_PROGRAMS = imap

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-storage

imap_LDADD = \
	../lib-storage/libstorage.a \
	../lib-storage/index/maildir/libstorage_maildir.a \
	../lib-storage/index/mbox/libstorage_mbox.a \
	../lib-storage/index/libstorage_index.a \
	../lib-index/maildir/libstorage_index_maildir.a \
	../lib-index/mbox/libstorage_index_mbox.a \
	../lib-index/libstorage_index.a \
	../lib-storage/subscription-file/libstorage_subscription_file.a \
	../lib-imap/libimap.a \
	../lib-mail/libmail.a \
	../lib/liblib.a

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
	cmd-list.c \
	cmd-login.c \
	cmd-logout.c \
	cmd-lsub.c \
	cmd-noop.c \
	cmd-rename.c \
	cmd-search.c \
	cmd-select.c \
	cmd-status.c \
	cmd-store.c \
	cmd-subscribe.c \
	cmd-uid.c \
	cmd-unsubscribe.c

imap_SOURCES = \
	$(cmds) \
	client.c \
	commands.c \
	commands-util.c \
	main.c

noinst_HEADERS = \
	client.h \
	commands.h \
	commands-util.h \
	common.h
