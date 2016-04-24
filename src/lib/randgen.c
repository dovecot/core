/* Copyright (c) 2002-2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "randgen.h"
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
	rand_set_seed(seed);

	fd_close_on_exec(urandom_fd, TRUE);
}

void random_deinit(void)
{
	if (--init_refcount > 0)
		return;

	i_close_fd(&urandom_fd);
}

#ifdef HAVE_ARC4RANDOM
#ifdef HAVE_LIBBSD
#include <bsd/stdlib.h>
#endif

void random_fill_weak(void *buf, size_t size)
{
	arc4random_buf(buf, size);
}

#else

void random_fill_weak(void *buf, size_t size)
{
	unsigned char *cbuf = buf;

	for (; size > 0; size--)
		*cbuf++ = (unsigned char)rand();
}

#endif
