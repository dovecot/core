noinst_LTLIBRARIES = liblib.la

BUILT_SOURCES = unicodemap.c

EXTRA_DIST = unicodemap.c unicodemap.pl UnicodeData.txt

UnicodeData.txt:
	test -f UnicodeData.txt || wget http://www.unicode.org/Public/UNIDATA/UnicodeData.txt

$(srcdir)/unicodemap.c: unicodemap.pl UnicodeData.txt
	perl $(srcdir)/unicodemap.pl < UnicodeData.txt > $@

liblib_la_SOURCES = \
	abspath.c \
	array.c \
	aqueue.c \
	askpass.c \
	backtrace-string.c \
	base64.c \
	bsearch-insert-pos.c \
	buffer.c \
	child-wait.c \
	compat.c \
	crc32.c \
	data-stack.c \
	eacces-error.c \
	env-util.c \
	execv-const.c \
	failures.c \
	fd-close-on-exec.c \
	fd-set-nonblock.c \
	fdatasync-path.c \
	fdpass.c \
	file-cache.c \
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
	hmac-md5.c \
	hmac-sha1.c \
	home-expand.c \
	hostpid.c \
	imem.c \
	ipwd.c \
	iostream.c \
	iostream-rawlog.c \
	iso8601-date.c \
	istream.c \
	istream-base64-encoder.c \
	istream-chain.c \
	istream-concat.c \
	istream-crlf.c \
	istream-data.c \
	istream-file.c \
	istream-limit.c \
	istream-mmap.c \
	istream-rawlog.c \
	istream-seekable.c \
	istream-sized.c \
	istream-tee.c \
	ioloop.c \
	ioloop-iolist.c \
	ioloop-notify-none.c \
	ioloop-notify-fd.c \
	ioloop-notify-dn.c \
	ioloop-notify-inotify.c \
	ioloop-notify-kqueue.c \
	ioloop-poll.c \
	ioloop-select.c \
	ioloop-epoll.c \
	ioloop-kqueue.c \
	lib.c \
	lib-signals.c \
	md4.c \
	md5.c \
	mempool.c \
	mempool-alloconly.c \
	mempool-datastack.c \
	mempool-system.c \
	mempool-unsafe-datastack.c \
	mkdir-parents.c \
	mmap-anon.c \
	mmap-util.c \
	module-dir.c \
	mountpoint.c \
	network.c \
	nfs-workarounds.c \
	ostream.c \
	ostream-file.c \
	ostream-buffer.c \
	ostream-rawlog.c \
	primes.c \
	printf-format-fix.c \
	process-title.c \
	priorityq.c \
	randgen.c \
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
	str.c \
	str-find.c \
	str-sanitize.c \
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
	wildcard-match.c \
	write-full.c

headers = \
	abspath.h \
	aqueue.h \
	array.h \
	array-decl.h \
	askpass.h \
	backtrace-string.h \
	base64.h \
	bsearch-insert-pos.h \
	buffer.h \
	child-wait.h \
	compat.h \
	crc32.h \
	data-stack.h \
	eacces-error.h \
	env-util.h \
	execv-const.h \
	failures.h \
	fd-close-on-exec.h \
	fd-set-nonblock.h \
	fdatasync-path.h \
	fdpass.h \
	file-cache.h \
	file-copy.h \
	file-dotlock.h \
	file-lock.h \
	file-set-size.h \
	fsync-mode.h \
	guid.h \
	hash.h \
	hash-format.h \
	hash-method.h \
	hash2.h \
	hex-binary.h \
	hex-dec.h \
	hmac-md5.h \
	hmac-sha1.h \
	home-expand.h \
	hostpid.h \
	imem.h \
	ipwd.h \
	iostream-private.h \
	iostream-rawlog.h \
	iostream-rawlog-private.h \
	iso8601-date.h \
	istream.h \
	istream-base64-encoder.h \
	istream-chain.h \
	istream-concat.h \
	istream-crlf.h \
	istream-private.h \
	istream-rawlog.h \
	istream-seekable.h \
	istream-sized.h \
	istream-tee.h \
	ioloop.h \
	ioloop-iolist.h \
	ioloop-private.h \
	ioloop-notify-fd.h \
	lib.h \
	lib-signals.h \
	llist.h \
	macros.h \
	md4.h \
	md5.h \
	mempool.h \
	mkdir-parents.h \
	mmap-util.h \
	module-context.h \
	module-dir.h \
	mountpoint.h \
	network.h \
	nfs-workarounds.h \
	ostream.h \
	ostream-private.h \
	ostream-rawlog.h \
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
	sha1.h \
	sha2.h \
	str.h \
	str-find.h \
	str-sanitize.h \
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
	test-base64.c \
	test-bsearch-insert-pos.c \
	test-buffer.c \
	test-crc32.c \
	test-hash-format.c \
	test-hex-binary.c \
	test-iso8601-date.c \
	test-istream-base64-encoder.c \
	test-istream-concat.c \
	test-istream-crlf.c \
	test-istream-seekable.c \
	test-istream-tee.c \
	test-llist.c \
	test-mempool-alloconly.c \
	test-network.c \
	test-ostream-file.c \
	test-primes.c \
	test-priorityq.c \
	test-seq-range-array.c \
	test-strescape.c \
	test-strfuncs.c \
	test-str-find.c \
	test-str-sanitize.c \
	test-time-util.c \
	test-utc-mktime.c \
	test-var-expand.c

test_headers = \
	test-lib.h

test_lib_LDADD = $(test_libs)
test_lib_DEPENDENCIES = $(test_libs)

check: check-am check-test
check-test: all-am
	for bin in $(test_programs); do \
	  if ! $(RUN_TEST) ./$$bin; then exit 1; fi; \
	done

pkginc_libdir=$(pkgincludedir)
pkginc_lib_HEADERS = $(headers)
noinst_HEADERS = $(test_headers)
