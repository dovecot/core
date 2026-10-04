#ifndef TEST_CORRUPTION_H
#define TEST_CORRUPTION_H

/* Called with each corrupted version of the data. The callback must not
   crash or access memory outside data[0..size-1]. */
typedef void test_corruption_callback_t(const unsigned char *data,
					size_t size, void *context);

struct test_corruption_settings {
	/* Name used when logging the random seed on crash */
	const char *name;
	/* Don't corrupt data before this offset, and don't truncate it to
	   be shorter than this. */
	size_t start_offset;
	/* Number of random corruptions. If 0, use the default. Can be
	   overridden with TEST_CORRUPTION_RANDOM_COUNT environment. */
	unsigned int random_count;
	/* If non-zero, limit the number of truncations and overwrites to
	   approximately this many by using larger steps. This is useful when
	   the callback is slow. Can be overridden with
	   TEST_CORRUPTION_MAX_DETERMINISTIC_COUNT environment (0 = no
	   limit). */
	unsigned int max_deterministic_count;
};

/* Call the callback with corrupted versions of data:

    - truncated at each offset
    - each 32bit word at 16bit steps overwritten with 0, 0x7fffffff and
      0xffffffff
    - random corruptions: random bytes, bit flips and 32bit values,
      sometimes combined with truncation

   Each corruption has an iteration number. The numbers depend on the data
   size and max_deterministic_count, so they change if either of them
   changes. The random corruptions are reproducible: they use a fixed seed
   by default, which can be changed with TEST_CORRUPTION_SEED environment.
   If the callback crashes, the seed and the iteration are logged.
   TEST_CORRUPTION_ITER environment can be used to run only the given
   iteration. TEST_CORRUPTION_RANDOM_ONLY environment skips the
   deterministic corruptions, and TEST_CORRUPTION_RANDOM_COUNT changes the
   number of random corruptions. With TEST_CORRUPTION_ITER,
   TEST_CORRUPTION_DUMP=<path prefix> writes the corrupted data to
   <path prefix>.<name>. */
void test_corruption_run(const struct test_corruption_settings *set,
			 const unsigned char *data, size_t size,
			 test_corruption_callback_t *callback, void *context);
#define test_corruption_run(set, data, size, callback, context) \
	test_corruption_run(set, data, size - \
		CALLBACK_TYPECHECK(callback, void (*)( \
			const unsigned char *, size_t, typeof(context))), \
		(test_corruption_callback_t *)callback, (void *)(context))

/* Apply one random corruption to data, using the given random state.
   Returns the new size, which is <= size. This can also be used by
   fuzzers. */
size_t test_corruption_random(unsigned char *data, size_t size,
			      size_t start_offset, uint64_t *rand_state);

#endif
