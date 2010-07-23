doveadm_moduledir = $(moduledir)/doveadm

bin_PROGRAMS = doveadm

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-dict \
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
	$(cmd_pw_libs) \
	$(unused_objects)

doveadm_LDADD = \
	$(libs) $(AUTH_LIBS) \
	$(LIBDOVECOT) \
	$(MODULE_LIBS)
doveadm_DEPENDENCIES = \
	$(libs) \
	$(LIBDOVECOT_DEPS)

doveadm_SOURCES = \
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
	doveadm-mail.c \
	doveadm-mail-altmove.c \
	doveadm-mail-expunge.c \
	doveadm-mail-fetch.c \
	doveadm-mail-iter.c \
	doveadm-mail-mailbox.c \
	doveadm-mail-mailbox-status.c \
	doveadm-mail-list-iter.c \
	doveadm-mail-search.c \
	doveadm-mutf7.c \
	doveadm-penalty.c \
	doveadm-print.c \
	doveadm-print-flow.c \
	doveadm-print-pager.c \
	doveadm-print-tab.c \
	doveadm-print-table.c \
	doveadm-pw.c \
	doveadm-settings.c \
	doveadm-util.c \
	doveadm-who.c

noinst_HEADERS = \
	doveadm.h \
	doveadm-dump.h \
	doveadm-mail.h \
	doveadm-mail-iter.h \
	doveadm-mail-list-iter.h \
	doveadm-print.h \
	doveadm-print-private.h \
	doveadm-settings.h \
	doveadm-util.h \
	doveadm-who.h
