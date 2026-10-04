/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "strnum.h"
#include "str.h"
#include "write-full.h"
#include "test-common.h"
#include "test-corruption.h"

#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#define TEST_CORRUPTION_DEFAULT_RANDOM_COUNT 1000
#define TEST_CORRUPTION_DEFAULT_SEED 1

static failure_callback_t *orig_fatal_callback;
static bool fatal_handler_set, crash_msg_active;
static char crash_msg[256];
static size_t crash_msg_len;
static struct sigaction orig_sigsegv, orig_sigbus;

static const uint32_t test_corruption_values[] = {
	0, 0x7fffffff, 0xffffffff
};

static const uint32_t test_corruption_random_values[] = {
	0, 1, 2, 3, 4, 7, 8, 0x7f, 0x80, 0xff, 0x100,
	0x7fff, 0x8000, 0xffff, 0x10000,
	0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff,
};

static uint64_t ATTR_UNSIGNED_WRAPS test_corruption_rand(uint64_t *state)
{
	/* splitmix64 */
	uint64_t z = (*state += 0x9e3779b97f4a7c15ULL);
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
	z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
	return z ^ (z >> 31);
}

static uint64_t test_corruption_rand_limit(uint64_t *state, uint64_t limit)
{
	i_assert(limit > 0);
	return test_corruption_rand(state) % limit;
}

static uint32_t ATTR_UNSIGNED_WRAPS
test_corruption_rand_value(uint64_t *state, size_t size)
{
	unsigned int n = N_ELEMENTS(test_corruption_random_values);

	switch (test_corruption_rand_limit(state, 4)) {
	case 0:
		return (uint32_t)test_corruption_rand(state);
	case 1:
		/* sizes and offsets close to the data size */
		return (uint32_t)(size + test_corruption_rand_limit(state, 16) - 8);
	default:
		return test_corruption_random_values[
			test_corruption_rand_limit(state, n)];
	}
}

size_t test_corruption_random(unsigned char *data, size_t size,
			      size_t start_offset, uint64_t *rand_state)
{
	unsigned int i, mutations_count;
	size_t offset, len, src;
	uint32_t value;
	uint16_t value16;

	if (size <= start_offset)
		return size;

	mutations_count = 1 + (test_corruption_rand_limit(rand_state, 4) == 0 ?
			       test_corruption_rand_limit(rand_state, 3) : 0);
	for (i = 0; i < mutations_count; i++) {
		offset = start_offset +
			test_corruption_rand_limit(rand_state,
						   size - start_offset);
		switch (test_corruption_rand_limit(rand_state, 5)) {
		case 0:
			/* random bytes */
			len = 1 + test_corruption_rand_limit(rand_state, 4);
			for (; len > 0 && offset < size; len--, offset++) {
				data[offset] = (unsigned char)
					test_corruption_rand(rand_state);
			}
			break;
		case 1:
			/* bit flip */
			data[offset] ^=
				1 << test_corruption_rand_limit(rand_state, 8);
			break;
		case 2:
			/* 32bit value */
			value = test_corruption_rand_value(rand_state, size);
			memcpy(data + offset, &value,
			       I_MIN(sizeof(value), size - offset));
			break;
		case 3:
			/* 16bit value */
			value16 = (uint16_t)
				test_corruption_rand_value(rand_state, size);
			memcpy(data + offset, &value16,
			       I_MIN(sizeof(value16), size - offset));
			break;
		case 4:
			/* copy data from another offset */
			src = start_offset +
				test_corruption_rand_limit(rand_state,
							   size - start_offset);
			len = 1 + test_corruption_rand_limit(rand_state, 32);
			len = I_MIN(len, I_MIN(size - offset, size - src));
			memmove(data + offset, data + src, len);
			break;
		}
	}
	if (test_corruption_rand_limit(rand_state, 8) == 0) {
		/* truncate also */
		size = start_offset +
			test_corruption_rand_limit(rand_state,
						   size - start_offset);
	}
	return size;
}

static void ATTR_NORETURN
test_corruption_fatal_handler(const struct failure_context *ctx,
			      const char *format, va_list args)
{
	if (crash_msg_active &&
	    write(STDERR_FILENO, crash_msg, crash_msg_len) < 0) {
		/* ignore */
	}
	orig_fatal_callback(ctx, format, args);
	i_unreached();
}

static void test_corruption_signal_handler(int signo)
{
	if (write(STDERR_FILENO, crash_msg, crash_msg_len) < 0) {
		/* ignore */
	}
	if (sigaction(signo, signo == SIGSEGV ? &orig_sigsegv : &orig_sigbus,
		      NULL) < 0)
		_exit(128 + signo);
	(void)raise(signo);
}

static void
test_corruption_set_crash_msg(const char *name, uint64_t seed,
			      unsigned int iter)
{
	int ret = i_snprintf(crash_msg, sizeof(crash_msg),
		"test_corruption(%s): Crashed with "
		"TEST_CORRUPTION_SEED=%"PRIu64" TEST_CORRUPTION_ITER=%u\n",
		name, seed, iter);
	crash_msg_len = ret < 0 ? 0 : strlen(crash_msg);
}

static void test_corruption_handlers_set(void)
{
	failure_callback_t *error_callback, *info_callback, *debug_callback;
	struct sigaction act = {
		.sa_handler = test_corruption_signal_handler,
	};

	if (!fatal_handler_set) {
		/* The fatal handler can't be restored, since it would need
		   to be ATTR_NORETURN. Keep it, but log only while active. */
		i_get_failure_handlers(&orig_fatal_callback, &error_callback,
				       &info_callback, &debug_callback);
		i_set_fatal_handler(test_corruption_fatal_handler);
		fatal_handler_set = TRUE;
	}
	crash_msg_active = TRUE;

	sigemptyset(&act.sa_mask);
	if (sigaction(SIGSEGV, &act, &orig_sigsegv) < 0)
		i_fatal("sigaction(SIGSEGV) failed: %m");
	if (sigaction(SIGBUS, &act, &orig_sigbus) < 0)
		i_fatal("sigaction(SIGBUS) failed: %m");
}

static void test_corruption_handlers_unset(void)
{
	crash_msg_active = FALSE;
	if (sigaction(SIGSEGV, &orig_sigsegv, NULL) < 0)
		i_fatal("sigaction(SIGSEGV) failed: %m");
	if (sigaction(SIGBUS, &orig_sigbus, NULL) < 0)
		i_fatal("sigaction(SIGBUS) failed: %m");
}

static uint64_t test_corruption_getenv_uint64(const char *name,
					      uint64_t default_value)
{
	const char *value = getenv(name);
	uint64_t num;

	if (value == NULL)
		return default_value;
	if (str_to_uint64(value, &num) < 0)
		i_fatal("Invalid %s=%s", name, value);
	return num;
}

static unsigned int
test_corruption_getenv_uint(const char *name, unsigned int default_value)
{
	const char *value = getenv(name);
	unsigned int num;

	if (value == NULL)
		return default_value;
	if (str_to_uint(value, &num) < 0)
		i_fatal("Invalid %s=%s", name, value);
	return num;
}

static size_t
test_corruption_get_iter(const struct test_corruption_settings *set,
			 const unsigned char *data, size_t size,
			 unsigned char *copy, uint64_t seed,
			 unsigned int truncate_step, unsigned int truncate_count,
			 unsigned int overwrite_step,
			 unsigned int overwrite_count, unsigned int iter)
{
	const unsigned int values_count = N_ELEMENTS(test_corruption_values);
	uint64_t rand_state;
	size_t offset, len;

	if (iter < truncate_count) {
		/* Truncate at the offset */
		len = set->start_offset + (size_t)iter * truncate_step;
		memcpy(copy, data, len);
		return len;
	}
	iter -= truncate_count;

	memcpy(copy, data, size);
	if (iter < overwrite_count) {
		/* Overwrite a 32bit word with an invalid value */
		offset = set->start_offset +
			(size_t)(iter / values_count) * overwrite_step;
		memcpy(copy + offset, &test_corruption_values[iter % values_count],
		       sizeof(test_corruption_values[0]));
		return size;
	}
	iter -= overwrite_count;

	/* Random corruption. Each iteration has its own seed, so they can be
	   reproduced individually. */
	rand_state = seed ^ ((uint64_t)iter << 32);
	rand_state = test_corruption_rand(&rand_state);
	return test_corruption_random(copy, size, set->start_offset,
				      &rand_state);
}

static void
test_corruption_dump(const char *name, const unsigned char *data, size_t size)
{
	const char *path = getenv("TEST_CORRUPTION_DUMP");

	if (path == NULL)
		return;
	path = t_strdup_printf("%s.%s", path, t_str_replace(name, ' ', '_'));
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd == -1)
		i_fatal("open(%s) failed: %m", path);
	if (write_full(fd, data, size) < 0)
		i_fatal("write(%s) failed: %m", path);
	i_close_fd(&fd);
	printf("test_corruption(%s): Wrote corrupted data to %s\n", name, path);
}

#undef test_corruption_run
void test_corruption_run(const struct test_corruption_settings *set,
			 const unsigned char *data, size_t size,
			 test_corruption_callback_t *callback, void *context)
{
	unsigned char *copy = i_malloc(size + 1);
	unsigned int truncate_step = 1, overwrite_step = sizeof(uint16_t);
	unsigned int truncate_count = 0, overwrite_count = 0;
	unsigned int random_count, iter, first_iter, last_iter;
	uint64_t seed, only_iter;
	size_t len, data_size;

	i_assert(set->start_offset <= size);
	data_size = size - set->start_offset;

	seed = test_corruption_getenv_uint64("TEST_CORRUPTION_SEED",
					     TEST_CORRUPTION_DEFAULT_SEED);
	random_count = set->random_count != 0 ? set->random_count :
		TEST_CORRUPTION_DEFAULT_RANDOM_COUNT;
	random_count = test_corruption_getenv_uint(
		"TEST_CORRUPTION_RANDOM_COUNT", random_count);
	only_iter = test_corruption_getenv_uint64("TEST_CORRUPTION_ITER",
						  UINT64_MAX);

	unsigned int max_deterministic_count = test_corruption_getenv_uint(
		"TEST_CORRUPTION_MAX_DETERMINISTIC_COUNT",
		set->max_deterministic_count);
	if (max_deterministic_count > 0) {
		/* Use larger steps to limit the number of iterations. */
		unsigned int max = max_deterministic_count;
		unsigned int values_count = N_ELEMENTS(test_corruption_values);

		while (data_size / truncate_step +
		       data_size / overwrite_step * values_count > max) {
			truncate_step++;
			overwrite_step += sizeof(uint16_t);
		}
	}
	/* Truncate at each offset */
	truncate_count = (data_size + truncate_step - 1) / truncate_step;
	/* Overwrite each 32bit word with invalid values. Use 16bit steps by
	   default, since many formats have 16bit fields at offsets that
	   aren't 32bit aligned. */
	if (data_size >= sizeof(uint32_t)) {
		overwrite_count = ((data_size - sizeof(uint32_t)) /
				   overwrite_step + 1) *
			N_ELEMENTS(test_corruption_values);
	}

	first_iter = getenv("TEST_CORRUPTION_RANDOM_ONLY") == NULL ? 0 :
		truncate_count + overwrite_count;
	last_iter = truncate_count + overwrite_count + random_count;
	if (only_iter != UINT64_MAX) {
		if (only_iter >= last_iter) {
			/* Not an error, since the same iteration is used for
			   all the test_corruption_run() calls. */
			printf("test_corruption(%s): Iteration %"PRIu64" is "
			       "out of range (only %u iterations)\n",
			       set->name, only_iter, last_iter);
			i_free(copy);
			return;
		}
		first_iter = only_iter;
		last_iter = only_iter + 1;
	}

	test_corruption_handlers_set();
	for (iter = first_iter; iter < last_iter; iter++) {
		len = test_corruption_get_iter(set, data, size, copy, seed,
					       truncate_step, truncate_count,
					       overwrite_step, overwrite_count,
					       iter);
		test_corruption_set_crash_msg(set->name, seed, iter);
		if (only_iter != UINT64_MAX)
			test_corruption_dump(set->name, copy, len);
		callback(copy, len, context);
	}
	test_corruption_handlers_unset();
	i_free(copy);
}
