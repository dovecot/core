SUBDIRS = index subscription-file

noinst_LIBRARIES = libstorage.a

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-imap

real_sources = \
	mail-search.c \
	mail-storage.c

libstorage_a_SOURCES = \
	$(real_sources) \
	mail-storage-register.c

noinst_HEADERS = \
	mail-search.h \
	mail-storage.h

DISTFILES = $(DIST_COMMON) $(real_sources) $(HEADERS) $(TEXINFOS) $(EXTRA_DIST)

distclean-generic:
	rm -f Makefile mail-storage-register.c
