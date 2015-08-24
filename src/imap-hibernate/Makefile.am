pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = imap-hibernate

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-imap

imap_hibernate_LDADD = $(LIBDOVECOT)
imap_hibernate_DEPENDENCIES = $(LIBDOVECOT_DEPS)

imap_hibernate_SOURCES = \
	imap-client.c \
	imap-hibernate-client.c \
	imap-hibernate-settings.c \
	imap-master-connection.c \
	main.c

noinst_HEADERS = \
	imap-client.h \
	imap-hibernate-client.h \
	imap-master-connection.h
