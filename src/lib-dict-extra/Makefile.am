noinst_LTLIBRARIES = libdict_extra.la

dict_drivers = @dict_drivers@

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-fs \
	-I$(top_srcdir)/src/lib-settings \
	$(SQL_CFLAGS)

libdict_extra_la_SOURCES = \
	dict-fs.c \
	dict-register.c
