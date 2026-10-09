/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "test-lib.h"
#include "array.h"
#include "strnum.h"
#include "str.h"
#include "unichar.h"
#include "unicode-data.h"
#include "unicode-transform.h"

static const struct casemap_test {
	const char *input;
	const char *lowercase;
	const char *uppercase;
	const char *casefold;
} tests[] = {
	{
		/* Wei<U+00DF>kopfseeadler */
		.input = "\x57\x65\x69\xC3\x9F\x6B\x6F\x70\x66"
			 "\x73\x65\x65\x61\x64\x6C\x65\x72",
		/* WEISSKOPFSEEADLER */
		.uppercase = "WEISSKOPFSEEADLER",
		/* wei<U+00DF>kopfseeadler */
		.lowercase = "\x77\x65\x69\xC3\x9F\x6B\x6F\x70"
			     "\x66\x73\x65\x65\x61\x64\x6C\x65\x72",
		/* weisskopfseeadler */
		.casefold = "weisskopfseeadler",
	},
	{
		/* aBcD<U+00C4><U+00E4> */
		.input = "aBcD\xC3\x84\xC3\xA4",
		/* ABCD<U+00C4><U+00C4> */
		.uppercase = "ABCD\xC3\x84\xC3\x84",
		/* abcd<U+00E4><U+00E4> */
		.lowercase = "abcd\xC3\xA4\xC3\xA4",
	}
};

static const unsigned int tests_count = N_ELEMENTS(tests);

/* Transform that accepts only a few code points at a time */
struct test_throttle_sink {
	struct unicode_transform transform;
	ARRAY_TYPE(uint32_t) *output;
	unsigned int calls;
};

static ssize_t
test_throttle_sink_input(struct unicode_transform *trans,
			 const struct unicode_transform_buffer *buf,
			 const char **error_r ATTR_UNUSED)
{
	struct test_throttle_sink *sink =
		container_of(trans, struct test_throttle_sink, transform);
	size_t count = I_MIN(buf->cp_count, sink->calls % 4 + 1);

	if (++sink->calls % 5 == 0)
		return 0;
	array_append(sink->output, buf->cp, count);
	return count;
}

static const struct unicode_transform_def test_throttle_sink_def = {
	.input = test_throttle_sink_input,
};

static ssize_t
test_array_sink_input(struct unicode_transform *trans,
		      const struct unicode_transform_buffer *buf,
		      const char **error_r ATTR_UNUSED)
{
	struct test_throttle_sink *sink =
		container_of(trans, struct test_throttle_sink, transform);

	array_append(sink->output, buf->cp, buf->cp_count);
	return buf->cp_count;
}

static const struct unicode_transform_def test_array_sink_def = {
	.input = test_array_sink_input,
};

/* Run the input through the casemap in chunks of chunk_size code points */
static void
test_casemap_run(struct unicode_casemap *map, const uint32_t *cps,
		 unsigned int count, unsigned int chunk_size, bool throttle,
		 ARRAY_TYPE(uint32_t) *output)
{
	struct test_throttle_sink sink;
	unsigned int loops = 0;
	size_t pos = 0;
	const char *error;
	ssize_t sret;
	int ret;

	i_zero(&sink);
	unicode_transform_init(&sink.transform, (throttle ?
						 &test_throttle_sink_def :
						 &test_array_sink_def));
	sink.output = output;
	map->transform.next = NULL;
	unicode_transform_chain(&map->transform, &sink.transform);

	array_clear(output);
	while (pos < count && ++loops < 10000) {
		sret = unicode_transform_input(&map->transform, &cps[pos],
					       I_MIN(count - pos, chunk_size),
					       &error);
		test_assert(sret >= 0);
		if (sret < 0)
			return;
		pos += sret;
	}
	do {
		ret = unicode_transform_flush(&map->transform, &error);
		test_assert(ret >= 0);
	} while (ret == 0 && ++loops < 10000);
	test_assert(pos == count);
	test_assert(loops < 10000);
}

static bool
test_arrays_equal(const ARRAY_TYPE(uint32_t) *arr1,
		  const ARRAY_TYPE(uint32_t) *arr2)
{
	if (array_count(arr1) != array_count(arr2))
		return FALSE;
	return array_count(arr1) == 0 ||
		memcmp(array_front(arr1), array_front(arr2),
		       array_count(arr1) * sizeof(uint32_t)) == 0;
}

static void
test_casemap_throttled_type(const ARRAY_TYPE(uint32_t) *input,
			    void (*init)(struct unicode_casemap *map),
			    size_t (*get_mapping)(
				const struct unicode_code_point_data *cp_data,
				const uint32_t **map_r))
{
	ARRAY_TYPE(uint32_t) output, expected;
	struct unicode_casemap map;
	const uint32_t *cps, *map_cps;
	unsigned int i, count;
	size_t map_len;

	t_array_init(&output, 256);
	t_array_init(&expected, 256);
	cps = array_get(input, &count);
	for (i = 0; i < count; i++) {
		map_len = get_mapping(unicode_code_point_get_data(cps[i]),
				      &map_cps);
		if (map_len == 0)
			array_push_back(&expected, &cps[i]);
		else
			array_append(&expected, map_cps, map_len);
	}

	init(&map);
	test_casemap_run(&map, cps, count, 50, TRUE, &output);
	test_assert(test_arrays_equal(&output, &expected));
}

static void test_casemap_throttled(void)
{
	/* Includes code points with multi-code point mappings */
	static const uint32_t pattern[] = {
		'a', 'B', 0x00df, 0x0149, 0xfb03, 0x0130, 0x03a3, 0x1e9e,
	};
	ARRAY_TYPE(uint32_t) input;
	unsigned int i;

	test_begin("unicode casemap throttled");
	t_array_init(&input, 256);
	for (i = 0; i < 200; i++)
		array_push_back(&input, &pattern[i % N_ELEMENTS(pattern)]);
	test_casemap_throttled_type(&input, unicode_casemap_init_uppercase,
		unicode_code_point_data_get_uppercase_mapping);
	test_casemap_throttled_type(&input, unicode_casemap_init_lowercase,
		unicode_code_point_data_get_lowercase_mapping);
	test_casemap_throttled_type(&input, unicode_casemap_init_casefold,
		unicode_code_point_data_get_casefold_mapping);
	test_end();
}

void test_unicode_casemap(void)
{
	unsigned int i;

	test_begin("unicode casemap");

	for (i = 0; i < tests_count; i++) {
		const struct casemap_test *test = &tests[i];
		const char *uppercase, *lowercase, *casefold;
		const char *test_casefold =
			(test->casefold != NULL ?
			 test->casefold : test->lowercase);
		int ret;

		ret = uni_utf8_to_uppercase(test->input, strlen(test->input),
					    &uppercase);
		test_assert_idx(ret >= 0, i);
		test_assert_strcmp_idx(test->uppercase, uppercase, i);

		ret = uni_utf8_to_lowercase(test->input, strlen(test->input),
					    &lowercase);
		test_assert_idx(ret >= 0, i);
		test_assert_strcmp_idx(test->lowercase, lowercase, i);

		ret = uni_utf8_to_casefold(test->input, strlen(test->input),
					   &casefold);
		test_assert_idx(ret >= 0, i);
		test_assert_strcmp_idx(test_casefold, casefold, i);
	}

	test_end();

	test_casemap_throttled();
}
