doveadm_moduledir = $(moduledir)/doveadm
pkglibexecdir = $(libexecdir)/dovecot

SUBDIRS = dsync

bin_PROGRAMS = doveadm
pkglibexec_PROGRAMS = doveadm-server

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-compression \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-fs \
	-I$(top_srcdir)/src/lib-ssl-iostream \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/auth \
	-DMODULEDIR=\""$(moduledir)"\" \
	-DDOVEADM_MODULEDIR=\""$(doveadm_moduledir)"\" \
	-DPKG_RUNDIR=\""$(rundir)"\" \
	-DPKG_STATEDIR=\""$(statedir)"\" \
	-DPKG_LIBEXECDIR=\""$(pkglibexecdir)"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DMANDIR=\""$(mandir)"\"

cmd_pw_libs = \
	../auth/libpassword.a \
	../lib-ntlm/libntlm.a \
	../lib-otp/libotp.a

libs = \
	dsync/libdsync.la \
	../lib-compression/libcompression.la

doveadm_LDADD = \
	$(libs) \
	$(cmd_pw_libs) \
	$(CRYPT_LIBS) \
	$(LIBDOVECOT_STORAGE) \
	$(LIBDOVECOT)
doveadm_DEPENDENCIES = \
	$(libs) \
	$(cmd_pw_libs) \
	$(LIBDOVECOT_STORAGE_DEPS) \
	$(LIBDOVECOT_DEPS)

doveadm_server_LDADD = \
	$(libs) \
	$(LIBDOVECOT_STORAGE) \
	$(LIBDOVECOT)
doveadm_server_DEPENDENCIES = \
	$(libs) \
	$(LIBDOVECOT_STORAGE_DEPS) \
	$(LIBDOVECOT_DEPS)

common = \
	doveadm-mail.c \
	doveadm-mail-altmove.c \
	doveadm-mail-batch.c \
	doveadm-mail-deduplicate.c \
	doveadm-mail-expunge.c \
	doveadm-mail-fetch.c \
	doveadm-mail-flags.c \
	doveadm-mail-import.c \
	doveadm-mail-index.c \
	doveadm-mail-iter.c \
	doveadm-mail-mailbox.c \
	doveadm-mail-mailbox-status.c \
	doveadm-mail-copymove.c \
	doveadm-mailbox-list-iter.c \
	doveadm-mail-search.c \
	doveadm-mail-server.c \
	doveadm-print.c \
	doveadm-settings.c \
	doveadm-util.c \
	server-connection.c

doveadm_SOURCES = \
	$(common) \
	doveadm.c \
	doveadm-auth.c \
	doveadm-director.c \
	doveadm-dump.c \
	doveadm-dump-dbox.c \
	doveadm-dump-index.c \
	doveadm-dump-log.c \
	doveadm-dump-mailboxlog.c \
	doveadm-dump-thread.c \
	doveadm-fs.c \
	doveadm-instance.c \
	doveadm-kick.c \
	doveadm-log.c \
	doveadm-master.c \
	doveadm-mount.c \
	doveadm-mutf7.c \
	doveadm-penalty.c \
	doveadm-print-flow.c \
	doveadm-print-pager.c \
	doveadm-print-tab.c \
	doveadm-print-table.c \
	doveadm-proxy.c \
	doveadm-pw.c \
	doveadm-replicator.c \
	doveadm-sis.c \
	doveadm-stats.c \
	doveadm-who.c \
	doveadm-zlib.c

doveadm_server_SOURCES = \
	$(common) \
	client-connection.c \
	doveadm-print-server.c \
	main.c

pkginc_libdir = $(pkgincludedir)
pkginc_lib_HEADERS = \
	doveadm.h \
	doveadm-dump.h \
	doveadm-mail.h \
	doveadm-mail-iter.h \
	doveadm-mailbox-list-iter.h \
	doveadm-print.h \
	doveadm-print-private.h \
	doveadm-settings.h \
	doveadm-util.h

noinst_HEADERS = \
	client-connection.h \
	server-connection.h \
	doveadm-server.h \
	doveadm-who.h

install-exec-local:
	rm -f $(DESTDIR)$(bindir)/dsync
	$(LN_S) doveadm $(DESTDIR)$(bindir)/dsync
