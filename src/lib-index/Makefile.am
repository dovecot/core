noinst_LIBRARIES = libindex.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-mail

libindex_a_SOURCES = \
	mail-cache.c \
	mail-cache-compress.c \
	mail-cache-decisions.c \
	mail-cache-fields.c \
	mail-cache-lookup.c \
	mail-cache-transaction.c \
	mail-cache-sync-update.c \
        mail-index.c \
        mail-index-fsck.c \
        mail-index-lock.c \
        mail-index-transaction.c \
        mail-index-transaction-view.c \
        mail-index-sync.c \
        mail-index-sync-ext.c \
        mail-index-sync-update.c \
        mail-index-view.c \
        mail-index-view-sync.c \
        mail-transaction-log.c \
        mail-transaction-log-view.c \
        mail-transaction-util.c

noinst_HEADERS = \
	mail-cache.h \
	mail-cache-private.h \
	mail-index.h \
	mail-index-private.h \
	mail-index-sync-private.h \
	mail-index-transaction-private.h \
	mail-index-view-private.h \
        mail-transaction-log.h \
	mail-transaction-log-private.h \
        mail-transaction-util.h
