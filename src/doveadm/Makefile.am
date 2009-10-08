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

doveadm_LDADD = \
	$(LIBDOVECOT_STORAGE) \
	$(LIBDOVECOT) \
	$(MODULE_LIBS)
doveadm_DEPENDENCIES = $(LIBDOVECOT_STORAGE) $(LIBDOVECOT)
doveadm_SOURCES = \
	doveadm.c \
	doveadm-mail.c

noinst_HEADERS = \
	doveadm-mail.h
