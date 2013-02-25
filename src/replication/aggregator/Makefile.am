pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = aggregator

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/replication \
	-DPKG_STATEDIR=\""$(statedir)"\"

aggregator_LDFLAGS = -export-dynamic
aggregator_LDADD = $(LIBDOVECOT)
aggregator_DEPENDENCIES = $(LIBDOVECOT_DEPS)

aggregator_SOURCES = \
	aggregator.c \
	aggregator-settings.c \
	notify-connection.c \
	replicator-connection.c

noinst_HEADERS = \
	aggregator-settings.h \
	notify-connection.h \
	replicator-connection.h
