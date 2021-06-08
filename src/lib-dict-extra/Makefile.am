noinst_LTLIBRARIES = libdict_extra.la

dict_drivers = @dict_drivers@

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-dict \
	-I$(top_srcdir)/src/lib-fs \
	-I$(top_srcdir)/src/lib-settings

libdict_extra_la_SOURCES = \
	dict-fs.c \
	dict-register.c

NOPLUGIN_LDFLAGS =

test_programs = \
	test-dict-fs

noinst_PROGRAMS = $(test_programs)

test_libs = \
	../lib-test/libtest.la \
	../lib-dict/libdict.la \
	../lib/liblib.la

test_dict_fs_SOURCES = test-dict-fs.c
test_dict_fs_LDADD = $(noinst_LTLIBRARIES) ../lib-fs/libfs.la $(test_libs) $(MODULE_LIBS)
test_dict_fs_DEPENDENCIES = $(noinst_LTLIBRARIES) ../lib-fs/libfs.la $(test_libs)

check-local:
	for bin in $(test_programs) $(check_PROGRAMS); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
