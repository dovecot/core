pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = replicator

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/replication \
	-DPKG_STATEDIR=\""$(statedir)"\"

replicator_LDFLAGS = -export-dynamic
replicator_LDADD = $(LIBDOVECOT)
replicator_DEPENDENCIES = $(LIBDOVECOT_DEPS)

replicator_SOURCES = \
	doveadm-connection.c \
	dsync-client.c \
	replicator.c \
	replicator-brain.c \
	replicator-queue.c \
	replicator-settings.c \
	notify-connection.c

noinst_HEADERS = \
	doveadm-connection.h \
	dsync-client.h \
	replicator-brain.h \
	replicator-queue.h \
	replicator-settings.h \
	notify-connection.h
