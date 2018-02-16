/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "randgen.h"
#include <unistd.h>
#include <fcntl.h>

/* get randomness from either getrandom, arc4random or /dev/urandom */

#if defined(HAVE_GETRANDOM) && HAVE_DECL_GETRANDOM != 0
#  include <sys/random.h>
#  define USE_GETRANDOM
static bool getrandom_present = TRUE;
#elif defined(HAVE_ARC4RANDOM)
#  if defined(HAVE_LIBBSD)
#    include <bsd/stdlib.h>
#  endif
#  define USE_ARC4RANDOM
#else
static bool getrandom_present = FALSE;
#  define USE_RANDOM_DEV
#endif

static int init_refcount = 0;
static int urandom_fd = -1;

#if defined(USE_GETRANDOM) || defined(USE_RANDOM_DEV)
static void random_open_urandom(void)
{
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
}

static inline int random_read(char *buf, size_t size)
{
	ssize_t ret = 0;
# if defined(USE_GETRANDOM)
	if (getrandom_present) {
		ret = getrandom(buf, size, 0);
		if (ret < 0 && errno == ENOSYS) {
			getrandom_present = FALSE;
			/* It gets complicated here...  While the libc (and its
			headers) indicated that getrandom() was available when
			we were compiled, the kernel disagreed just now at
			runtime. Fall back to reading /dev/urandom. */
			random_open_urandom();
		}
	}
	/* this is here to avoid clang complain,
	   because getrandom_present will be always FALSE
	   if USE_GETRANDOM is not defined */
	if (!getrandom_present)
# endif
		ret = read(urandom_fd, buf, size);
	if (unlikely(ret <= 0)) {
		if (ret == 0) {
			i_fatal("read("DEV_URANDOM_PATH") failed: EOF");
		} else if (errno != EINTR) {
			if (getrandom_present) {
				i_fatal("getrandom() failed: %m");
			} else {
				i_fatal("read("DEV_URANDOM_PATH") failed: %m");
			}
		}
	}
	i_assert(ret > 0 || errno == EINTR);
	return ret;
}
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
		ret = random_read(PTR_OFFSET(buf, pos), size - pos);
		if (ret > -1)
			pos += ret;
	}
#endif /* defined(USE_ARC4RANDOM) */
}

void random_init(void)
{
	unsigned int seed;

	if (init_refcount++ > 0)
		return;
#if defined(USE_RANDOM_DEV)
	random_open_urandom();
#endif
	/* DO NOT REMOVE THIS - It is also
	   needed to make sure getrandom really works.
	*/
	random_fill(&seed, sizeof(seed));
	srand(seed);
}

void random_deinit(void)
{
	if (--init_refcount > 0)
		return;
	i_close_fd(&urandom_fd);
}
