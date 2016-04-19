pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = imap-hibernate

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-imap \
	$(BINARY_CFLAGS)

imap_hibernate_LDADD = $(LIBDOVECOT) \
	$(BINARY_LDFLAGS)

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
