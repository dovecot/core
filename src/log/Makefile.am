pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = log

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master

log_LDADD = $(LIBDOVECOT)
log_DEPENDENCIES = $(LIBDOVECOT_DEPS)

log_SOURCES = \
	log-connection.c \
	log-settings.c \
	main.c

noinst_HEADERS = \
	log-connection.h
