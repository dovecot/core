noinst_LIBRARIES = libsql.a

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	$(SQL_CFLAGS)

libsql_a_SOURCES = \
	driver-mysql.c \
	driver-pgsql.c \
	sql-api.c

noinst_HEADERS = \
	sql-api.h \
	sql-api-private.h
