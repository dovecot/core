noinst_LIBRARIES = libstorage-register.a

INCLUDES = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-storage

libstorage_register_a_SOURCES = \
	mail-storage-register.c

DISTFILES = $(DIST_COMMON) $(HEADERS) $(TEXINFOS) $(EXTRA_DIST)

distclean-generic:
	rm -f Makefile mail-storage-register.c
