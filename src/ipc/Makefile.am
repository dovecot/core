pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = ipc

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	$(BINARY_CFLAGS)

ipc_LDADD = $(LIBDOVECOT) \
	$(BINARY_LDFLAGS)
ipc_DEPENDENCIES = $(LIBDOVECOT_DEPS)

ipc_SOURCES = \
	client.c \
	main.c \
	ipc-connection.c \
	ipc-group.c \
	ipc-settings.c

noinst_HEADERS = \
	client.h \
	ipc-connection.h \
	ipc-group.h
