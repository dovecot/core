stats_moduledir = $(moduledir)/stats
pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = stats

AM_CPPFLAGS = \
	-DSTATS_MODULE_DIR=\""$(stats_moduledir)"\" \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-stats \
	$(BINARY_CFLAGS)

stats_LDADD = $(LIBDOVECOT) \
	$(BINARY_LDFLAGS)

stats_DEPENDENCIES = $(LIBDOVECOT_DEPS)

stats_SOURCES = \
	client.c \
	client-export.c \
	client-reset.c \
	fifo-input-connection.c \
	global-memory.c \
	mail-command.c \
	mail-domain.c \
	mail-ip.c \
	mail-session.c \
	mail-stats.c \
	mail-user.c \
	main.c \
	stats-settings.c

noinst_HEADERS = \
	client.h \
	client-export.h \
	client-reset.h \
	fifo-input-connection.h \
	global-memory.h \
	mail-command.h \
	mail-domain.h \
	mail-ip.h \
	mail-session.h \
	mail-stats.h \
	mail-user.h \
	stats-settings.h
