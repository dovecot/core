noinst_LIBRARIES = libstorage_dbox.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index

libstorage_dbox_a_SOURCES = \
	dbox-file.c \
	dbox-keywords.c \
	dbox-list.c \
	dbox-mail.c \
	dbox-save.c \
	dbox-sync.c \
	dbox-sync-expunge.c \
	dbox-sync-full.c \
	dbox-storage.c \
	dbox-transaction.c \
	dbox-uidlist.c

noinst_HEADERS = \
	dbox-file.h \
	dbox-format.h \
	dbox-keywords.h \
	dbox-storage.h \
	dbox-sync.h \
	dbox-uidlist.h
