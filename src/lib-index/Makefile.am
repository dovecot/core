SUBDIRS = maildir mbox

noinst_LIBRARIES = libindex.a

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap

libindex_a_SOURCES = \
	mail-custom-flags.c \
        mail-index.c \
        mail-index-compress.c \
        mail-index-file.c \
        mail-index-fsck.c \
        mail-index-data.c \
        mail-index-open.c \
        mail-index-update.c \
        mail-index-update-cache.c \
        mail-index-util.c \
	mail-modifylog.c

noinst_HEADERS = \
	mail-custom-flags.h \
	mail-index.h \
        mail-index-data.h \
        mail-index-util.h \
	mail-modifylog.h \
	mail-tree.h
