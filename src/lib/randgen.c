/* Copyright (c) 2002-2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "randgen.h"

#include <stdlib.h>

#ifdef HAVE_DEV_URANDOM

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

	for (pos = 0; pos < size; pos += ret) {
		ret = read(urandom_fd, (char *) buf + pos, size - pos);
		if (ret < 0 && errno != EINTR)
			i_fatal("Error reading from /dev/urandom: %m");
	}
}

void random_init(void)
{
	unsigned int seed;

	if (init_refcount++ > 0)
		return;

	urandom_fd = open("/dev/urandom", O_RDONLY);
	if (urandom_fd == -1) {
		if (errno == ENOENT) {
			i_fatal("/dev/urandom doesn't exist, "
				"currently we require it");
		} else {
			i_fatal("Can't open /dev/urandom: %m");
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

#include <sys/time.h>
#ifdef HAVE_SYS_RESOURCE_H
#  include <sys/resource.h>
#endif

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

static void random_init_rng(void)
{
	unsigned int counter = 0;
	struct timeval tv;
#ifdef HAVE_GETRUSAGE
	struct rusage ru;
#endif

	/* If the RNG is already seeded, we can return immediately. */
	if (RAND_status() == 1)
		return;

	/* Else, try to seed it. Unfortunately we don't have
	   /dev/urandom, so we can only use weak random sources. */
	while (RAND_status() != 1) {
		if (gettimeofday(&tv, NULL) < 0)
			i_fatal("gettimeofday() failed: %m");
		RAND_add(&tv, sizeof(tv), sizeof(tv) / 2);
#ifdef HAVE_GETRUSAGE
		if (getrusage(RUSAGE_SELF, &ru) < 0)
			i_fatal("getrusage() failed: %m");
		RAND_add(&ru, sizeof(ru), sizeof(ru) / 2);
#endif

		if (counter++ > 100) {
			i_fatal("Random generator initialization failed: "
				"Couldn't get enough entropy");
		}
	}
}

void random_fill(void *buf, size_t size)
{
	if (RAND_bytes(buf, size) != 1)
		i_fatal("RAND_pseudo_bytes() failed: %s", ssl_last_error());
}

void random_init(void)
{
	unsigned int seed;

	random_init_rng();

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
