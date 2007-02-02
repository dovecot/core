pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = pop3

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-storage \
	-DMODULEDIR=\""$(moduledir)"\"

pop3_LDFLAGS = -export-dynamic

# get some functions included which only plugins use. liblib should probably
# be a shared library so this wouldn't be needed..
unused_objects = \
	../lib/mountpoint.o \
	../lib/str-sanitize.o

libs = \
	../lib-storage/register/libstorage-register.a \
	../lib-storage/list/libstorage_list.a \
	$(STORAGE_LIBS) \
	../lib-storage/libstorage.a \
	../lib-imap/libimap.a \
	../lib-mail/libmail.a \
	../lib-dict/libdict.a \
	../lib-charset/libcharset.a \
	../lib/liblib.a \
	$(unused_objects)

pop3_LDADD = \
	$(libs) \
	$(LIBICONV) \
	$(RAND_LIBS) \
	$(MODULE_LIBS)

pop3_DEPENDENCIES = $(libs)

pop3_SOURCES = \
	client.c \
	commands.c \
	mail-storage-callbacks.c \
	main.c

noinst_HEADERS = \
	capability.h \
	client.h \
	commands.h \
	common.h
