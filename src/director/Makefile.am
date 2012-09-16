pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = director

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-auth \
	-I$(top_srcdir)/src/lib-imap \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master \
	-I$(top_srcdir)/src/lib-mail

director_LDADD = $(LIBDOVECOT)
director_DEPENDENCIES = $(LIBDOVECOT_DEPS)

director_SOURCES = \
	main.c \
	auth-connection.c \
	director.c \
	director-connection.c \
	director-host.c \
	director-request.c \
	director-settings.c \
	doveadm-connection.c \
	login-connection.c \
	mail-host.c \
	notify-connection.c \
	user-directory.c

noinst_HEADERS = \
	auth-connection.h \
	director.h \
	director-connection.h \
	director-host.h \
	director-request.h \
	director-settings.h \
	doveadm-connection.h \
	login-connection.h \
	mail-host.h \
	notify-connection.h \
	user-directory.h

noinst_PROGRAMS = director-test $(test_programs)

director_test_LDADD = $(LIBDOVECOT)
director_test_DEPENDENCIES = $(LIBDOVECOT_DEPS)

director_test_SOURCES = \
	director-test.c

test_programs = \
	test-user-directory

test_libs = \
	../lib-test/libtest.la \
	../lib/liblib.la

test_user_directory_SOURCES = test-user-directory.c
test_user_directory_LDADD = user-directory.o $(test_libs)
test_user_directory_DEPENDENCIES = $(pkglibexec_PROGRAMS) $(test_libs)

check: check-am check-test
check-test: all-am
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
