pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = dict

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-sql \
	-DDICT_MODULE_DIR=\""$(moduledir)/dict"\" \
	-DPKG_RUNDIR=\""$(rundir)"\"

dict_LDFLAGS = -export-dynamic

libs = \
	../lib-dict/libdict_backend.a \
	$(LIBDOVECOT_SQL)

dict_LDADD = \
	$(libs) \
	$(LIBDOVECOT) \
	$(MODULE_LIBS) \
	$(DICT_LIBS) \
	$(SQL_LIBS)
dict_DEPENDENCIES = $(libs) $(LIBDOVECOT_DEPS)

dict_SOURCES = \
	dict-connection.c \
	dict-commands.c \
	dict-settings.c \
	main.c

noinst_HEADERS = \
	dict-connection.h \
	dict-commands.h \
	dict-settings.h
