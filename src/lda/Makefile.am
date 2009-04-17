pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = dovecot-lda

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-mail \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-index \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-lda \
	-I$(top_srcdir)/src/lib-storage \
	-I$(top_srcdir)/src/lib-storage/index \
	-I$(top_srcdir)/src/lib-storage/index/raw \
	-DPKG_RUNDIR=\""$(rundir)"\"

dovecot_lda_LDFLAGS = -export-dynamic

if !BUILD_SHARED_LIBS
unused_objects = \
	../lib/mountpoint.o \
	../lib-imap/imap-util.o
endif

libs = \
	../lib-lda/liblda.a \
	$(LIBDOVECOT_STORAGE) \
	$(LIBDOVECOT) \
	$(unused_objects)

dovecot_lda_LDADD = $(libs) $(MODULE_LIBS)

dovecot_lda_DEPENDENCIES = $(libs)

dovecot_lda_SOURCES = \
	main.c
