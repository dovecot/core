pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = imap

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-DPKG_RUNDIR=\""$(rundir)"\" \
	-DMODULEDIR=\""$(moduledir)"\"

imap_LDFLAGS = -export-dynamic

libs = \
	../lib-storage/libdovecot-storage.la \
	../lib-dovecot/libdovecot.la

imap_LDADD = \
	$(libs)

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
	cmd-id.c \
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
	imap-search-args.c \
	imap-settings.c \
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
	imap-search-args.h \
	imap-settings.h \
	imap-status.h \
	imap-sync.h

if INSTALL_HEADERS
  pkginc_libdir=$(pkgincludedir)/src/imap
  pkginc_lib_HEADERS = $(headers)
else
  noinst_HEADERS = $(headers)
endif
