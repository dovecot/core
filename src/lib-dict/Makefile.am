noinst_LIBRARIES = libdict.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-sql \
	$(SQL_CFLAGS)

libdict_a_SOURCES = \
	dict.c \
	dict-sql.c

noinst_HEADERS = \
	dict.h \
	dict-private.h
