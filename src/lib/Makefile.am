noinst_LIBRARIES = liblib.a

if IOLOOP_POLL
ioloop_source = ioloop-poll.c
else
ioloop_source = ioloop-select.c
endif

ioloop_sources = \
	ioloop-poll.c \
	ioloop-select.c

liblib_a_SOURCES = \
	base64.c \
	compat.c \
	failures.c \
	fdpass.c \
	file-set-size.c \
	gmtoff.c \
	hash.c \
	hex-binary.c \
	hostpid.c \
	imem.c \
	iobuffer.c \
	ioloop.c \
	$(ioloop_source) \
	lib.c \
	lib-signals.c \
	md5.c \
	mempool.c \
	mempool-alloconly.c \
	mempool-system.c \
	mmap-util.c \
	network.c \
	primes.c \
	randgen.c \
	restrict-access.c \
	sendfile-util.c \
	strfuncs.c \
	temp-mempool.c \
	temp-string.c \
	unlink-directory.c \
	unlink-lockfiles.c \
	write-full.c

noinst_HEADERS = \
	base64.h \
	compat.h \
	failures.h \
	fdpass.h \
	file-set-size.h \
	gmtoff.h \
	hash.h \
	hex-binary.h \
	hostpid.h \
	imem.h \
	iobuffer.h \
	ioloop.h \
	ioloop-internal.h \
	lib.h \
	lib-signals.h \
	macros.h \
	md5.h \
	mempool.h \
	mmap-util.h \
	network.h \
	primes.h \
	randgen.h \
	restrict-access.h \
	sendfile-util.h \
	strfuncs.h \
	temp-mempool.h \
	temp-string.h \
	unlink-directory.h \
	unlink-lockfiles.h \
	write-full.h

EXTRA_DIST = \
	$(ioloop_sources)
