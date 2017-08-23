/* Copyright (c) 2002-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "randgen.h"
#include "fd-close-on-exec.h"
#include <unistd.h>
#include <fcntl.h>

/* get randomness from either getrandom, arc4random or /dev/urandom */

#if defined(HAVE_GETRANDOM) && HAVE_DECL_GETRANDOM != 0
#  include <sys/random.h>
#  define USE_GETRANDOM
#elif defined(HAVE_ARC4RANDOM)
#  if defined(HAVE_LIBBSD)
#    include <bsd/stdlib.h>
#  endif
#  define USE_ARC4RANDOM
#else
#  define USE_RANDOM_DEV
#endif

static int init_refcount = 0;
#if defined(USE_RANDOM_DEV)
static int urandom_fd;
#endif

void random_fill(void *buf, size_t size)
{
	i_assert(init_refcount > 0);
	i_assert(size < SSIZE_T_MAX);

#if defined(USE_ARC4RANDOM)
	arc4random_buf(buf, size);
#else
	size_t pos;
	ssize_t ret;

	for (pos = 0; pos < size; ) {
#  if defined(USE_GETRANDOM)
		ret = getrandom(buf, size - pos, 0);
#  else
		ret = read(urandom_fd, (char *) buf + pos, size - pos);
#  endif
		if (unlikely(ret <= 0)) {
			if (ret == 0)
				i_fatal("read("DEV_URANDOM_PATH") failed: EOF");
			else if (errno != EINTR)
#  if defined(USE_RANDOM_DEV)
				i_fatal("read("DEV_URANDOM_PATH") failed: %m");
#  elif defined(USE_GETRANDOM)
				i_fatal("getrandom() failed: %m");
#  endif
		} else {
			pos += ret;
		}
	}
#endif /* defined(USE_ARC4RANDOM) */
}

void random_init(void)
{
	unsigned int seed;

	if (init_refcount++ > 0)
		return;
#if defined(USE_RANDOM_DEV)
	urandom_fd = open(DEV_URANDOM_PATH, O_RDONLY);
	if (urandom_fd == -1) {
		if (errno == ENOENT) {
			i_fatal("open("DEV_URANDOM_PATH") failed: doesn't exist,"
				"currently we require it");
		} else {
			i_fatal("open("DEV_URANDOM_PATH") failed: %m");
		}
	}
	fd_close_on_exec(urandom_fd, TRUE);
#endif
	random_fill(&seed, sizeof(seed));
	srand(seed);
}

void random_deinit(void)
{
	if (--init_refcount > 0)
		return;
#if defined(USE_RANDOM_DEV)
	i_close_fd(&urandom_fd);
#endif
}
