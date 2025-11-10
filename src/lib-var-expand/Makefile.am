include $(top_srcdir)/Makefile.test.include

noinst_LTLIBRARIES = libvar_expand.la

# Squelch autoconf error about using .[ly] sources but not defining $(LEX)
# and $(YACC).  Using false here avoids accidental use.
LEX=/bin/false
YACC=/bin/false

# We use custom rules here because we want to use flex and bison instead
# of lex and yacc (or bison in yacc-compatibility mode).  Both flex and
# bison can handle properly naming the generated files, and it is simpler
# and cleaner to make this rule ourselves instead of working around ylwrap
# and yywrap's antiquated notion of what is happening.
.l.c:
	$(AM_V_GEN)$(FLEX) -o $@ $<

.y.c:
	$(AM_V_GEN)$(BISON) -o $@ $<

AM_CPPFLAGS = \
	-I$(top_srcdir)/src/lib \
	-I$(top_srcdir)/src/lib-test \
	-I$(top_srcdir)/src/lib-regex \
	-Wno-error=unused-function \
	-DVAR_EXPAND_MODULE_DIR=\"$(moduledir)\"

var-expand-parser.h: var-expand-parser.c

libvar_expand_la_SOURCES = \
	expansion-parameter.c \
	expansion-statement.c \
	expansion-filter.c \
	expansion-filter-if.c \
	expansion-filter-crypt.c \
	expansion-program.c \
	var-expand.c \
	var-expand-parser.y \
	var-expand-lexer.l

BUILT_SOURCES = \
	var-expand-parser.c \
	var-expand-parser.h \
	var-expand-lexer.c

noinst_HEADERS = \
	var-expand-parser-private.h \
	var-expand-parser.h \
	expansion.h

headers = \
	var-expand.h \
	var-expand-private.h

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)

test_programs = \
	test-var-expand

test_libs = \
	libvar_expand.la \
	../lib-regex/libdregex.la \
	../lib-test/libtest.la \
	../lib/liblib.la \
	$(MODULE_LIBS)

test_var_expand_SOURCE = test-var-expand.c
test_var_expand_LDADD = $(test_libs)

if USE_FUZZER
fuzz_programs = fuzz-var-expand

nodist_EXTRA_fuzz_var_expand_SOURCES = force-cxx-linking.cxx

fuzz_var_expand_CPPFLAGS = $(FUZZER_CPPFLAGS)
fuzz_var_expand_LDFLAGS = $(FUZZER_LDFLAGS)
fuzz_var_expand_SOURCES = fuzz-var-expand.c
fuzz_var_expand_LDADD = $(test_libs)
fuzz_var_expand_DEPENDENCIES = libvar_expand.la

noinst_PROGRAMS += $(fuzz_programs)

endif

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done
