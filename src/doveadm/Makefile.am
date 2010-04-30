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
	-DPKG_RUNDIR=\""$(rundir)"\"

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
	doveadm-dump.c \
	doveadm-dump-index.c \
	doveadm-dump-log.c \
	doveadm-dump-mailboxlog.c \
	doveadm-dump-thread.c \
	doveadm-kick.c \
	doveadm-mail.c \
	doveadm-mail-altmove.c \
	doveadm-mail-expunge.c \
	doveadm-mail-fetch.c \
	doveadm-mail-iter.c \
	doveadm-mail-list.c \
	doveadm-mail-list-iter.c \
	doveadm-mail-search.c \
	doveadm-penalty.c \
	doveadm-pw.c \
	doveadm-settings.c \
	doveadm-who.c

noinst_HEADERS = \
	doveadm.h \
	doveadm-dump.h \
	doveadm-mail.h \
	doveadm-mail-iter.h \
	doveadm-mail-list-iter.h \
	doveadm-settings.h \
	doveadm-who.h
