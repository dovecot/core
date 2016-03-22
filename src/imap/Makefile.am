pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = imap

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-lda \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-imap-urlauth \
	-I$(top_srcdir)/src/lib-imap-storage \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage

imap_LDFLAGS = -export-dynamic

imap_LDADD = \
	../lib-imap-urlauth/libimap-urlauth.la \
	$(LIBDOVECOT_LDA) \
	$(LIBDOVECOT_STORAGE) \
	$(LIBDOVECOT)
imap_DEPENDENCIES = \
	../lib-imap-urlauth/libimap-urlauth.la \
	$(LIBDOVECOT_LDA) \
	$(LIBDOVECOT_STORAGE_DEPS) \
	$(LIBDOVECOT_DEPS)

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
	cmd-genurlauth.c \
	cmd-getmetadata.c \
	cmd-id.c \
	cmd-idle.c \
	cmd-list.c \
	cmd-logout.c \
	cmd-lsub.c \
	cmd-namespace.c \
	cmd-noop.c \
	cmd-notify.c \
	cmd-rename.c \
	cmd-resetkey.c \
	cmd-search.c \
	cmd-select.c \
	cmd-setmetadata.c \
	cmd-sort.c \
	cmd-status.c \
	cmd-store.c \
	cmd-subscribe.c \
	cmd-thread.c \
	cmd-unselect.c \
	cmd-unsubscribe.c \
	cmd-urlfetch.c \
	cmd-x-cancel.c \
	cmd-x-state.c

imap_SOURCES = \
	$(cmds) \
	imap-client.c \
	imap-client-hibernate.c \
	imap-commands.c \
	imap-commands-util.c \
	imap-expunge.c \
	imap-fetch.c \
	imap-fetch-body.c \
	imap-list.c \
	imap-master-client.c \
	imap-notify.c \
	imap-search.c \
	imap-search-args.c \
	imap-settings.c \
	imap-status.c \
	imap-state.c \
	imap-sync.c \
	mail-storage-callbacks.c \
	main.c

headers = \
	imap-client.h \
	imap-commands.h \
	imap-commands-util.h \
	imap-common.h \
	imap-expunge.h \
	imap-fetch.h \
	imap-list.h \
	imap-master-client.h \
	imap-notify.h \
	imap-search.h \
	imap-search-args.h \
	imap-settings.h \
	imap-status.h \
	imap-state.h \
	imap-sync.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
