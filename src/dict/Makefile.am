pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = dict

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-sql \
	-DDICT_MODULE_DIR=\""$(moduledir)/dict"\" \
	-DPKG_RUNDIR=\""$(rundir)"\"

dict_LDFLAGS = -export-dynamic

libs = \
	../lib-dict/libdict.a \
	../lib-sql/libsql.a \
	../lib/liblib.a

dict_LDADD = \
	$(libs) \
	$(RAND_LIBS) \
	$(MODULE_LIBS) \
	$(DICT_LIBS) \
	$(SQL_LIBS)

dict_DEPENDENCIES = $(libs)

dict_SOURCES = \
	dict-cache.c \
	dict-server.c \
	main.c

noinst_HEADERS = \
	dict-cache.h \
	dict-server.h
