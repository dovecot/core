SUBDIRS = index subscription-file register

noinst_LIBRARIES = libstorage.a

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-imap

libstorage_a_SOURCES = \
	mail-search.c \
	mail-sort.c \
	mail-storage.c

noinst_HEADERS = \
	mail-search.h \
	mail-sort.h \
	mail-storage.h
