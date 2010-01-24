/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "randgen.h"

#include <stdlib.h>

#ifdef DEV_URANDOM_PATH

#include "fd-close-on-exec.h"
#include <unistd.h>
#include <fcntl.h>

static int init_refcount = 0;
static int urandom_fd;

void random_fill(void *buf, size_t size)
{
	size_t pos;
	ssize_t ret;

	i_assert(init_refcount > 0);
	i_assert(size < SSIZE_T_MAX);

	for (pos = 0; pos < size; ) {
		ret = read(urandom_fd, (char *) buf + pos, size - pos);
		if (unlikely(ret <= 0)) {
			if (ret == 0)
				i_fatal("EOF when reading from "DEV_URANDOM_PATH);
			else if (errno != EINTR)
				i_fatal("read("DEV_URANDOM_PATH") failed: %m");
		} else {
			pos += ret;
		}
	}
}

void random_init(void)
{
	unsigned int seed;

	if (init_refcount++ > 0)
		return;

	urandom_fd = open(DEV_URANDOM_PATH, O_RDONLY);
	if (urandom_fd == -1) {
		if (errno == ENOENT) {
			i_fatal(DEV_URANDOM_PATH" doesn't exist, "
				"currently we require it");
		} else {
			i_fatal("Can't open "DEV_URANDOM_PATH": %m");
		}
	}

	random_fill(&seed, sizeof(seed));
	srand(seed);

	fd_close_on_exec(urandom_fd, TRUE);
}

void random_deinit(void)
{
	if (--init_refcount > 0)
		return;

	(void)close(urandom_fd);
	urandom_fd = -1;
}

#elif defined(HAVE_OPENSSL_RAND_H)
#include <openssl/rand.h>
#include <openssl/err.h>

static const char *ssl_last_error(void)
{
	unsigned long err;
	char *buf;
	size_t err_size = 256;

	err = ERR_get_error();
	if (err == 0)
		return strerror(errno);

	buf = t_malloc(err_size);
	buf[err_size-1] = '\0';
	ERR_error_string_n(err, buf, err_size-1);
	return buf;
}

void random_fill(void *buf, size_t size)
{
	if (RAND_bytes(buf, size) != 1)
		i_fatal("RAND_pseudo_bytes() failed: %s", ssl_last_error());
}

void random_init(void)
{
	unsigned int seed;

	if (RAND_status() == 0) {
		i_fatal("Random generator not initialized: "
			"Install egd on /var/run/egd-pool");
	}

	random_fill(&seed, sizeof(seed));
	srand(seed);
}

void random_deinit(void) {}

#else
#  error No random number generator, use eg. OpenSSL.
#endif

void random_fill_weak(void *buf, size_t size)
{
	unsigned char *cbuf = buf;

	for (; size > 0; size--)
		*cbuf++ = (unsigned char)rand();
}
