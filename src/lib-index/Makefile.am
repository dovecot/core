SUBDIRS = maildir mbox

noinst_LIBRARIES = libindex.a

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap

libindex_a_SOURCES = \
        mail-cache.c \
	mail-custom-flags.c \
        mail-index.c \
        mail-index-file.c \
        mail-index-fsck.c \
        mail-index-open.c \
        mail-index-rebuild.c \
        mail-index-util.c \
	mail-modifylog.c

noinst_HEADERS = \
        mail-cache.h \
	mail-custom-flags.h \
	mail-index.h \
        mail-index-util.h \
	mail-modifylog.h
