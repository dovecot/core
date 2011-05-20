doveadm_moduledir = $(moduledir)/doveadm
pkglibexecdir = $(libexecdir)/dovecot

bin_PROGRAMS = doveadm
pkglibexec_PROGRAMS = doveadm-server

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-fs \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/auth \
	-DMODULEDIR=\""$(moduledir)"\" \
	-DDOVEADM_MODULEDIR=\""$(doveadm_moduledir)"\" \
	-DPKG_RUNDIR=\""$(rundir)"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DMANDIR=\""$(mandir)"\"

if !BUILD_SHARED_LIBS
unused_objects = \
	../lib/mountpoint.o \
	../lib-imap/imap-util.o \
	../lib-storage/mail-search-parser-imap.o
endif

cmd_pw_libs = \
	../auth/libpassword.a \
	../lib-ntlm/libntlm.a \
	../lib-otp/libotp.a

libs = \
	$(LIBDOVECOT_STORAGE) \
	$(unused_objects)

doveadm_LDADD = \
	$(libs) \
	$(cmd_pw_libs) \
	$(AUTH_LIBS) \
	$(LIBDOVECOT) \
	$(MODULE_LIBS)
doveadm_DEPENDENCIES = \
	$(libs) \
	$(cmd_pw_libs) \
	$(LIBDOVECOT_DEPS)

doveadm_server_LDADD = \
	$(libs) \
	$(LIBDOVECOT) \
	$(MODULE_LIBS)
doveadm_server_DEPENDENCIES = \
	$(libs) \
	$(LIBDOVECOT_DEPS)

common = \
	doveadm-mail.c \
	doveadm-mail-altmove.c \
	doveadm-mail-expunge.c \
	doveadm-mail-fetch.c \
	doveadm-mail-import.c \
	doveadm-mail-index.c \
	doveadm-mail-iter.c \
	doveadm-mail-mailbox.c \
	doveadm-mail-mailbox-status.c \
	doveadm-mail-move.c \
	doveadm-mail-list-iter.c \
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
	doveadm-dump-index.c \
	doveadm-dump-log.c \
	doveadm-dump-mailboxlog.c \
	doveadm-dump-thread.c \
	doveadm-kick.c \
	doveadm-log.c \
	doveadm-master.c \
	doveadm-mutf7.c \
	doveadm-penalty.c \
	doveadm-print-flow.c \
	doveadm-print-pager.c \
	doveadm-print-tab.c \
	doveadm-print-table.c \
	doveadm-proxy.c \
	doveadm-pw.c \
	doveadm-sis.c \
	doveadm-who.c

doveadm_server_SOURCES = \
	$(common) \
	client-connection.c \
	doveadm-print-server.c \
	main.c

noinst_HEADERS = \
	client-connection.h \
	server-connection.h \
	doveadm.h \
	doveadm-dump.h \
	doveadm-mail.h \
	doveadm-mail-iter.h \
	doveadm-mail-list-iter.h \
	doveadm-print.h \
	doveadm-print-private.h \
	doveadm-server.h \
	doveadm-settings.h \
	doveadm-util.h \
	doveadm-who.h
