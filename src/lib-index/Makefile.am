SUBDIRS = maildir mbox

noinst_LIBRARIES = libstorage_index.a

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap

libstorage_index_a_SOURCES = \
	mail-custom-flags.c \
	mail-hash.c \
        mail-index.c \
        mail-index-compress.c \
        mail-index-fsck.c \
        mail-index-data.c \
        mail-index-update.c \
        mail-index-update-cache.c \
        mail-index-util.c \
        mail-lockdir.c \
	mail-modifylog.c

noinst_HEADERS = \
	mail-custom-flags.h \
	mail-hash.h \
	mail-index.h \
        mail-index-data.h \
        mail-index-util.h \
        mail-lockdir.h \
	mail-modifylog.h
