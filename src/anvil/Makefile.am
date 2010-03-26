pkglibexecdir = $(libexecdir)/dovecot

pkglibexec_PROGRAMS = anvil

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-settings \
	-I$(top_srcdir)/src/lib-master

anvil_LDADD = \
	$(LIBDOVECOT) \
	$(MODULE_LIBS) \
	$(RAND_LIBS)
anvil_DEPENDENCIES = $(LIBDOVECOT_DEPS)

anvil_SOURCES = \
	main.c \
	anvil-connection.c \
	anvil-settings.c \
	connect-limit.c \
	penalty.c

noinst_HEADERS = \
	anvil-connection.h \
	common.h \
	connect-limit.h \
	penalty.h

test_programs = \
	test-penalty

noinst_PROGRAMS = $(test_programs)

test_libs = \
	../lib-test/libtest.la \
	../lib/liblib.la

test_penalty_SOURCES = test-penalty.c
test_penalty_LDADD = penalty.o $(test_libs)
test_penalty_DEPENDENCIES = penalty.o $(test_libs)

check: check-am check-test
check-test: all-am
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
