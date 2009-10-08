bin_PROGRAMS = doveadm

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/auth \
	-DPKG_RUNDIR=\""$(rundir)"\"

cmd_pw_libs = \
	../auth/libpassword.a \
	../lib-ntlm/libntlm.a \
	../lib-otp/libotp.a

doveadm_LDADD = \
	$(cmd_pw_libs) $(AUTH_LIBS) \
	$(LIBDOVECOT_STORAGE) \
	$(LIBDOVECOT) \
	$(MODULE_LIBS)
doveadm_DEPENDENCIES = \
	$(cmd_pw_libs) \
	$(LIBDOVECOT_STORAGE) \
	$(LIBDOVECOT)

doveadm_SOURCES = \
	doveadm.c \
	doveadm-auth.c \
	doveadm-mail.c \
	doveadm-pw.c

noinst_HEADERS = \
	doveadm-mail.h
