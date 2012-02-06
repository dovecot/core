pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = log

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master

log_LDADD = $(LIBDOVECOT)
log_DEPENDENCIES = $(LIBDOVECOT_DEPS)

log_SOURCES = \
	doveadm-connection.c \
	log-connection.c \
	log-error-buffer.c \
	log-settings.c \
	main.c

noinst_HEADERS = \
	doveadm-connection.h \
	log-connection.h \
	log-error-buffer.h
