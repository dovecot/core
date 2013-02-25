pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = stats

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master

stats_LDADD = $(LIBDOVECOT) 
stats_DEPENDENCIES = $(LIBDOVECOT_DEPS)

stats_SOURCES = \
	client.c \
	client-export.c \
	global-memory.c \
	mail-command.c \
	mail-domain.c \
	mail-ip.c \
	mail-server-connection.c \
	mail-session.c \
	mail-stats.c \
	mail-user.c \
	main.c \
	stats-settings.c

noinst_HEADERS = \
	client.h \
	client-export.h \
	global-memory.h \
	mail-command.h \
	mail-domain.h \
	mail-ip.h \
	mail-server-connection.h \
	mail-session.h \
	mail-stats.h \
	mail-user.h \
	stats-settings.h
