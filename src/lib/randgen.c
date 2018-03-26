/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "randgen.h"
#include <unistd.h>
#include <fcntl.h>

#ifdef DEBUG
/* For reproducing tests, fall back onto using a simple deterministic PRNG */
/* Marsaglia's 1999 KISS, de-macro-ified, and with the fixed KISS11 SHR3,
   which is clearly what was intended given the "cycle length 2^123" claim. */
static bool kiss_in_use;
static unsigned int kiss_seed;
static uint32_t kiss_z, kiss_w, kiss_jsr, kiss_jcong;
static void
kiss_init(unsigned int seed)
{
	i_info("Random numbers are PRNG using kiss, as per DOVECOT_SRAND=%u", seed);
	kiss_seed = seed;
	kiss_jsr = 0x5eed5eed; /* simply musn't be 0 */
	kiss_z = 1 ^ (kiss_w = kiss_jcong = seed); /* w=z=0 is bad, see Rose */
	kiss_in_use = TRUE;
}
static unsigned int
kiss_rand(void)
{
	kiss_z = 36969 * (kiss_z&65535) + (kiss_z>>16);
	kiss_w = 18000 * (kiss_w&65535) + (kiss_w>>16);
	kiss_jcong = 69069 * kiss_jcong + 1234567;
	kiss_jsr^=(kiss_jsr<<13); /* <<17, >>13 gives cycle length 2^28.2 max */
	kiss_jsr^=(kiss_jsr>>17); /* <<13, >>17 gives maximal cycle length */
	kiss_jsr^=(kiss_jsr<<5);
	return (((kiss_z<<16) + kiss_w) ^ kiss_jcong) + kiss_jsr;
}
int rand_get_last_seed(unsigned int *seed_r)
{
	if (!kiss_in_use)
		return -1; /* not using a deterministic PRNG, seed is irrelevant */
	*seed_r = kiss_seed;
	return 0;
}
#endif

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

#ifdef DEBUG
	if (kiss_in_use) {
		for (size_t pos = 0; pos < size; pos++)
			((unsigned char*)buf)[pos] = kiss_rand();
		return;
	}
#endif

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
	/* static analyzer seems to require this */
	unsigned int seed = 0;
	const char *env_seed;

	if (init_refcount++ > 0)
		return;

	env_seed = getenv("DOVECOT_SRAND");
#ifdef DEBUG
	if (env_seed != NULL && str_to_uint(env_seed, &seed) >= 0) {
		kiss_init(seed);
		/* getrandom_present = FALSE; not needed, only used in random_read() */
		goto normal_exit;
	}
#else
	if (env_seed != NULL && *env_seed != '\0')
		i_warning("DOVECOT_SRAND is not available in non-debug builds");
#endif /* DEBUG */

#if defined(USE_RANDOM_DEV)
	random_open_urandom();
#endif
	/* DO NOT REMOVE THIS - It is also
	   needed to make sure getrandom really works.
	*/
	random_fill(&seed, sizeof(seed));
#ifdef DEBUG
	if (env_seed != NULL) {
		if (strcmp(env_seed, "kiss") != 0)
			i_fatal("DOVECOT_SRAND not a number or 'kiss'");
		kiss_init(seed);
		i_close_fd(&urandom_fd);
	}

normal_exit:
#endif
	srand(seed);
}

void random_deinit(void)
{
	if (--init_refcount > 0)
		return;
	i_close_fd(&urandom_fd);
}
