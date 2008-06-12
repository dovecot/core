pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = imap

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-DMODULEDIR=\""$(moduledir)"\"

imap_LDFLAGS = -export-dynamic

# get some functions included which only plugins use. liblib should probably
# be a shared library so this wouldn't be needed..
unused_objects = \
	../lib/mountpoint.o

libs = \
	../lib-storage/register/libstorage-register.a \
	../lib-storage/list/libstorage_list.a \
	$(STORAGE_LIBS) \
	../lib-imap/libimap.a \
	../lib-mail/libmail.a \
	../lib-dict/libdict.a \
	../lib-charset/libcharset.a \
	../lib/liblib.a \
	$(unused_objects)

imap_LDADD = \
	$(libs) \
	$(LIBICONV) \
	$(MODULE_LIBS)

imap_DEPENDENCIES = $(libs)

cmds = \
	cmd-append.c \
	cmd-capability.c \
	cmd-cancelupdate.c \
	cmd-check.c \
	cmd-close.c \
	cmd-copy.c \
	cmd-create.c \
	cmd-delete.c \
	cmd-enable.c \
	cmd-examine.c \
	cmd-expunge.c \
	cmd-fetch.c \
	cmd-idle.c \
	cmd-list.c \
	cmd-logout.c \
	cmd-lsub.c \
	cmd-namespace.c \
	cmd-noop.c \
	cmd-rename.c \
	cmd-search.c \
	cmd-select.c \
	cmd-sort.c \
	cmd-status.c \
	cmd-store.c \
	cmd-subscribe.c \
	cmd-thread.c \
	cmd-uid.c \
	cmd-unselect.c \
	cmd-unsubscribe.c \
	cmd-x-cancel.c

imap_SOURCES = \
	$(cmds) \
	client.c \
	commands.c \
	commands-util.c \
	imap-expunge.c \
	imap-fetch.c \
	imap-fetch-body.c \
	imap-search.c \
	imap-sort.c \
	imap-status.c \
	imap-sync.c \
	mail-storage-callbacks.c \
	main.c


headers = \
	client.h \
	commands.h \
	commands-util.h \
	common.h \
	imap-expunge.h \
	imap-fetch.h \
	imap-search.h \
	imap-sort.h \
	imap-status.h \
	imap-sync.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)/src/imap
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif
