AM_CPPFLAGS = \
	$(LIBUNWIND_CFLAGS)

noinst_LTLIBRARIES = liblib.la

BUILT_SOURCES = $(srcdir)/unicodemap.c \
		event-filter-parser-lexer.c \
		event-filter-parser-parser.c \
		event-filter-parser-parser.h

EXTRA_DIST = unicodemap.c unicodemap.pl UnicodeData.txt

# Squelch autoconf error about using .[ly] sources but not defining $(LEX)
# and $(YACC).  Using false here avoids accidental use.
LEX=/bin/false
YACC=/bin/false

# We use custom rules here because we want to use flex and bison instead
# of lex and yacc (or bison in yacc-compatibility mode).  Both flex and
# bison can handle properly naming the generated files, and it is simpler
# and cleaner to make this rule ourselves instead of working around ylwrap
# and yywrap's antiquated notion of what is hapenning.
.l.c:
	$(AM_V_GEN)$(FLEX) -o $@ $<

.y.c:
	$(AM_V_GEN)$(BISON) -o $@ $<

# Bison generates both a header and a .c file.  Without the following
# dependency, anything including the header will race the bison process.
event-filter-parser-parser.h: event-filter-parser-parser.c

$(srcdir)/UnicodeData.txt:
	test -f $@ || wget -O $@ https://dovecot.org/res/UnicodeData.txt

$(srcdir)/unicodemap.c: $(srcdir)/unicodemap.pl $(srcdir)/UnicodeData.txt
	perl $(srcdir)/unicodemap.pl < $(srcdir)/UnicodeData.txt > $@

liblib_la_LIBADD = $(LIBUNWIND_LIBS)
liblib_la_SOURCES = \
	array.c \
	aqueue.c \
	askpass.c \
	backtrace-string.c \
	base32.c \
	base64.c \
	bits.c \
	bsearch-insert-pos.c \
	buffer.c \
	child-wait.c \
	compat.c \
	connection.c \
	crc32.c \
	data-stack.c \
	eacces-error.c \
	env-util.c \
	event-filter.c \
	event-filter-parser-lexer.l \
	event-filter-parser-parser.y \
	event-log.c \
	execv-const.c \
	failures.c \
	fd-util.c \
	fdatasync-path.c \
	fdpass.c \
	file-cache.c \
	file-create-locked.c \
	file-copy.c \
	file-dotlock.c \
	file-lock.c \
	file-set-size.c \
	guid.c \
	hash.c \
	hash-format.c \
	hash-method.c \
	hash2.c \
	hex-binary.c \
	hex-dec.c \
	hmac.c \
	hmac-cram-md5.c \
	home-expand.c \
	hook-build.c \
	hostpid.c \
	imem.c \
	ipwd.c \
	iostream.c \
	iostream-pump.c \
	iostream-proxy.c \
	iostream-rawlog.c \
	iostream-temp.c \
	iso8601-date.c \
	istream.c \
	istream-base64-decoder.c \
	istream-base64-encoder.c \
	istream-callback.c \
	istream-chain.c \
	istream-concat.c \
	istream-crlf.c \
	istream-data.c \
	istream-failure-at.c \
	istream-file.c \
	istream-hash.c \
	istream-jsonstr.c \
	istream-limit.c \
	istream-mmap.c \
	istream-multiplex.c \
	istream-rawlog.c \
	istream-seekable.c \
	istream-sized.c \
	istream-tee.c \
	istream-try.c \
	istream-timeout.c \
	istream-unix.c \
	ioloop.c \
	ioloop-iolist.c \
	ioloop-notify-none.c \
	ioloop-notify-fd.c \
	ioloop-notify-inotify.c \
	ioloop-notify-kqueue.c \
	ioloop-poll.c \
	ioloop-select.c \
	ioloop-epoll.c \
	ioloop-kqueue.c \
	json-parser.c \
	json-tree.c \
	lib.c \
	lib-event.c \
	lib-signals.c \
	log-throttle.c \
	md4.c \
	md5.c \
	memarea.c \
	mempool.c \
	mempool-allocfree.c \
	mempool-alloconly.c \
	mempool-datastack.c \
	mempool-system.c \
	mempool-unsafe-datastack.c \
	mkdir-parents.c \
	mmap-anon.c \
	mmap-util.c \
	module-dir.c \
	mountpoint.c \
	net.c \
	nfs-workarounds.c \
	numpack.c \
	ostream.c \
	ostream-buffer.c \
	ostream-failure-at.c \
	ostream-file.c \
	ostream-hash.c \
	ostream-multiplex.c \
	ostream-null.c \
	ostream-rawlog.c \
	ostream-unix.c \
	ostream-wrapper.c \
	path-util.c \
	pkcs5.c \
	primes.c \
	printf-format-fix.c \
	process-title.c \
	priorityq.c \
	randgen.c \
	rand.c \
	read-full.c \
	restrict-access.c \
	restrict-process-size.c \
	safe-memset.c \
	safe-mkdir.c \
	safe-mkstemp.c \
	sendfile-util.c \
	seq-range-array.c \
	sha1.c \
	sha2.c \
	sha3.c \
	sleep.c \
	sort.c \
	stats-dist.c \
	str.c \
	str-find.c \
	str-sanitize.c \
	str-table.c \
	strescape.c \
	strfuncs.c \
	strnum.c \
	time-util.c \
	unix-socket-create.c \
	unlink-directory.c \
	unlink-old-files.c \
	unichar.c \
	uri-util.c \
	utc-offset.c \
	utc-mktime.c \
	var-expand.c \
	var-expand-if.c \
	wildcard-match.c \
	write-full.c

headers = \
	aqueue.h \
	array.h \
	array-decl.h \
	askpass.h \
	backtrace-string.h \
	base32.h \
	base64.h \
	bits.h \
	bsearch-insert-pos.h \
	buffer.h \
	byteorder.h \
	child-wait.h \
	compat.h \
	connection.h \
	crc32.h \
	data-stack.h \
	eacces-error.h \
	env-util.h \
	event-filter.h \
	event-filter-parser-parser.h \
	event-filter-private.h \
	event-log.h \
	execv-const.h \
	failures.h \
	failures-private.h \
	fd-util.h \
	fdatasync-path.h \
	fdpass.h \
	file-cache.h \
	file-create-locked.h \
	file-copy.h \
	file-dotlock.h \
	file-lock.h \
	file-set-size.h \
	fsync-mode.h \
	guid.h \
	hash.h \
	hash-decl.h \
	hash-format.h \
	hash-method.h \
	hash2.h \
	hex-binary.h \
	hex-dec.h \
	hmac.h \
	hmac-cram-md5.h \
	home-expand.h \
	hook-build.h \
	hostpid.h \
	imem.h \
	ipwd.h \
	iostream.h \
	iostream-private.h \
	iostream-pump.h \
	iostream-proxy.h \
	iostream-rawlog.h \
	iostream-rawlog-private.h \
	iostream-temp.h \
	iso8601-date.h \
	istream.h \
	istream-base64.h \
	istream-callback.h \
	istream-chain.h \
	istream-concat.h \
	istream-crlf.h \
	istream-failure-at.h \
	istream-file-private.h \
	istream-hash.h \
	istream-jsonstr.h \
	istream-multiplex.h \
	istream-private.h \
	istream-rawlog.h \
	istream-seekable.h \
	istream-sized.h \
	istream-tee.h \
	istream-try.h \
	istream-timeout.h \
	istream-unix.h \
	ioloop.h \
	ioloop-iolist.h \
	ioloop-private.h \
	ioloop-notify-fd.h \
	json-parser.h \
	json-tree.h \
	lib.h \
	lib-event.h \
	lib-event-private.h \
	lib-signals.h \
	llist.h \
	log-throttle.h \
	macros.h \
	md4.h \
	md5.h \
	malloc-overflow.h \
	memarea.h \
	mempool.h \
	mkdir-parents.h \
	mmap-util.h \
	module-context.h \
	module-dir.h \
	mountpoint.h \
	net.h \
	nfs-workarounds.h \
	numpack.h \
	ostream.h \
	ostream-failure-at.h \
	ostream-file-private.h \
	ostream-hash.h \
	ostream-multiplex.h \
	ostream-private.h \
	ostream-null.h \
	ostream-rawlog.h \
	ostream-unix.h \
	ostream-wrapper.h \
	path-util.h \
	pkcs5.h \
	primes.h \
	printf-format-fix.h \
	process-title.h \
	priorityq.h \
	randgen.h \
	read-full.h \
	restrict-access.h \
	restrict-process-size.h \
	safe-memset.h \
	safe-mkdir.h \
	safe-mkstemp.h \
	sendfile-util.h \
	seq-range-array.h \
	sha-common.h \
	sha1.h \
	sha2.h \
	sha3.h \
	sleep.h \
	sort.h \
	stats-dist.h \
	str.h \
	str-find.h \
	str-sanitize.h \
	str-table.h \
	strescape.h \
	strfuncs.h \
	strnum.h \
	time-util.h \
	unix-socket-create.h \
	unlink-directory.h \
	unlink-old-files.h \
	unichar.h \
	uri-util.h \
	utc-offset.h \
	utc-mktime.h \
	var-expand.h \
	var-expand-private.h \
	wildcard-match.h \
	write-full.h

test_programs = test-lib
noinst_PROGRAMS = $(test_programs)

test_lib_CPPFLAGS = \
	-I$(top_srcdir)/src/lib-test

test_libs = \
	../lib-test/libtest.la \
	liblib.la

test_lib_SOURCES = \
	test-lib.c \
	test-array.c \
	test-aqueue.c \
	test-backtrace.c \
	test-base32.c \
	test-base64.c \
	test-bits.c \
	test-bsearch-insert-pos.c \
	test-buffer.c \
	test-byteorder.c \
	test-connection.c \
	test-crc32.c \
	test-data-stack.c \
	test-event-category-register.c \
	test-event-filter.c \
	test-event-flatten.c \
	test-event-log.c \
	test-failures.c \
	test-fd-util.c \
	test-file-create-locked.c \
	test-guid.c \
	test-hash.c \
	test-hash-format.c \
	test-hash-method.c \
	test-hmac.c \
	test-hex-binary.c \
	test-imem.c \
	test-ioloop.c \
	test-iso8601-date.c \
	test-iostream-pump.c \
	test-iostream-proxy.c \
	test-iostream-temp.c \
	test-istream.c \
	test-istream-base64-decoder.c \
	test-istream-base64-encoder.c \
	test-istream-chain.c \
	test-istream-concat.c \
	test-istream-crlf.c \
	test-istream-failure-at.c \
	test-istream-jsonstr.c \
	test-istream-multiplex.c \
	test-istream-seekable.c \
	test-istream-sized.c \
	test-istream-tee.c \
	test-istream-try.c \
	test-istream-unix.c \
	test-json-parser.c \
	test-json-tree.c \
	test-lib-signals.c \
	test-llist.c \
	test-log-throttle.c \
	test-malloc-overflow.c \
	test-memarea.c \
	test-mempool.c \
	test-mempool-allocfree.c \
	test-mempool-alloconly.c \
	test-pkcs5.c \
	test-net.c \
	test-numpack.c \
	test-ostream-buffer.c \
	test-ostream-failure-at.c \
	test-ostream-file.c \
	test-ostream-multiplex.c \
	test-multiplex.c \
	test-path-util.c \
	test-primes.c \
	test-printf-format-fix.c \
	test-priorityq.c \
	test-random.c \
	test-seq-range-array.c \
	test-stats-dist.c \
	test-str.c \
	test-strescape.c \
	test-strfuncs.c \
	test-strnum.c \
	test-str-find.c \
	test-str-sanitize.c \
	test-str-table.c \
	test-time-util.c \
	test-unichar.c \
	test-utc-mktime.c \
	test-uri.c \
	test-var-expand.c \
	test-wildcard-match.c

test_headers = \
	test-lib.h \
	test-lib.inc

test_lib_LDADD = $(test_libs) -lm
test_lib_DEPENDENCIES = $(test_libs)

check-local:
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
noinst_HEADERS = $(test_headers)
