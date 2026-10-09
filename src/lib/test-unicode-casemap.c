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

static void
test_utf8_to_cps(const char *str, ARRAY_TYPE(uint32_t) *dest)
{
	const unsigned char *data = (const unsigned char *)str;
	size_t size = strlen(str);
	unichar_t chr;
	int bytes;

	array_clear(dest);
	while (size > 0) {
		bytes = uni_utf8_get_char_n(data, size, &chr);
		i_assert(bytes > 0);
		array_push_back(dest, &chr);
		data += bytes;
		size -= bytes;
	}
}

#define CAPITAL_ALPHA "\xCE\x91"
#define CAPITAL_SIGMA "\xCE\xA3"
#define SMALL_ALPHA "\xCE\xB1"
#define SMALL_SIGMA "\xCF\x83"
#define SMALL_FINAL_SIGMA "\xCF\x82"
#define ACUTE "\xCC\x81"
#define ACUTE_10 ACUTE ACUTE ACUTE ACUTE ACUTE ACUTE ACUTE ACUTE ACUTE ACUTE

static void test_casemap_final_sigma(void)
{
	static const struct {
		const char *input, *output;
	} tests[] = {
		{ CAPITAL_ALPHA CAPITAL_SIGMA, SMALL_ALPHA SMALL_FINAL_SIGMA },
		{ CAPITAL_ALPHA CAPITAL_SIGMA CAPITAL_ALPHA,
		  SMALL_ALPHA SMALL_SIGMA SMALL_ALPHA },
		{ CAPITAL_SIGMA, SMALL_SIGMA },
		{ "1" CAPITAL_SIGMA, "1" SMALL_SIGMA },
		{ CAPITAL_ALPHA CAPITAL_SIGMA "'" CAPITAL_ALPHA,
		  SMALL_ALPHA SMALL_SIGMA "'" SMALL_ALPHA },
		{ CAPITAL_ALPHA CAPITAL_SIGMA "'",
		  SMALL_ALPHA SMALL_FINAL_SIGMA "'" },
		{ CAPITAL_ALPHA "'" CAPITAL_SIGMA,
		  SMALL_ALPHA "'" SMALL_FINAL_SIGMA },
		{ CAPITAL_ALPHA CAPITAL_SIGMA CAPITAL_SIGMA,
		  SMALL_ALPHA SMALL_SIGMA SMALL_FINAL_SIGMA },
		{ CAPITAL_ALPHA CAPITAL_SIGMA " " CAPITAL_ALPHA CAPITAL_SIGMA,
		  SMALL_ALPHA SMALL_FINAL_SIGMA " "
		  SMALL_ALPHA SMALL_FINAL_SIGMA },
		/* Up to 31 case-ignorable code points are checked */
		{ CAPITAL_ALPHA CAPITAL_SIGMA ACUTE_10 ACUTE_10 ACUTE_10 ACUTE
		  CAPITAL_ALPHA,
		  SMALL_ALPHA SMALL_SIGMA ACUTE_10 ACUTE_10 ACUTE_10 ACUTE
		  SMALL_ALPHA },
		{ CAPITAL_ALPHA CAPITAL_SIGMA ACUTE_10 ACUTE_10 ACUTE_10 ACUTE
		  ACUTE CAPITAL_ALPHA,
		  SMALL_ALPHA SMALL_FINAL_SIGMA ACUTE_10 ACUTE_10 ACUTE_10 ACUTE
		  ACUTE SMALL_ALPHA },
	};
	static const unsigned int chunk_sizes[] = { 1, 2, 100 };
	ARRAY_TYPE(uint32_t) input, output, expected;
	struct unicode_casemap map;
	unsigned int i, j, throttle;

	test_begin("unicode casemap final sigma");
	t_array_init(&input, 64);
	t_array_init(&output, 64);
	t_array_init(&expected, 64);
	unicode_casemap_init_lowercase_final_sigma(&map);
	for (i = 0; i < N_ELEMENTS(tests); i++) {
		test_utf8_to_cps(tests[i].input, &input);
		test_utf8_to_cps(tests[i].output, &expected);
		for (j = 0; j < N_ELEMENTS(chunk_sizes); j++) {
			for (throttle = 0; throttle < 2; throttle++) {
				test_casemap_run(&map, array_front(&input),
						 array_count(&input),
						 chunk_sizes[j], throttle == 1,
						 &output);
				test_assert_idx(test_arrays_equal(&output,
								  &expected),
						i * 10 + j * 2 + throttle);
			}
		}
	}

	/* The context doesn't continue from the previous string */
	test_utf8_to_cps(CAPITAL_ALPHA, &input);
	test_casemap_run(&map, array_front(&input), array_count(&input), 100,
			 FALSE, &output);
	test_utf8_to_cps(CAPITAL_SIGMA, &input);
	test_utf8_to_cps(SMALL_SIGMA, &expected);
	test_casemap_run(&map, array_front(&input), array_count(&input), 100,
			 FALSE, &output);
	test_assert(test_arrays_equal(&output, &expected));

	/* Unchanged without final sigma handling */
	unicode_casemap_init_lowercase(&map);
	test_utf8_to_cps(CAPITAL_ALPHA CAPITAL_SIGMA, &input);
	test_utf8_to_cps(SMALL_ALPHA SMALL_SIGMA, &expected);
	test_casemap_run(&map, array_front(&input), array_count(&input), 100,
			 FALSE, &output);
	test_assert(test_arrays_equal(&output, &expected));
	test_end();
}

static bool
test_final_sigma_ref_is_final(const uint32_t *cps, unsigned int count,
			      unsigned int pos)
{
	const struct unicode_code_point_data *cp_data;
	unsigned int i;

	for (i = pos; i > 0; i--) {
		cp_data = unicode_code_point_get_data(cps[i - 1]);
		if (!cp_data->pb_c_case_ignorable)
			break;
	}
	if (i == 0 || !cp_data->pb_c_cased)
		return FALSE;

	for (i = pos + 1; i < count; i++) {
		cp_data = unicode_code_point_get_data(cps[i]);
		if (!cp_data->pb_c_case_ignorable)
			return !cp_data->pb_c_cased;
		if (i - pos >= UNICODE_CASEMAP_BUFFER_SIZE) {
			/* Too many case-ignorable code points */
			return TRUE;
		}
	}
	return TRUE;
}

static void test_casemap_final_sigma_random(void)
{
	static const uint32_t pool[] = {
		0x03a3, 0x03a3, 0x03a3, 0x0391, 'a', 'B', '1', ' ', '\'',
		0x0301, 0x0301, 0x0301, 0x02b0, 0x0345, 0x00df, 0x0130,
	};
	ARRAY_TYPE(uint32_t) input, output, expected;
	struct unicode_casemap map;
	const uint32_t *cps, *map_cps;
	unsigned int i, j, k, count;
	size_t map_len;
	uint32_t cp;

	test_begin("unicode casemap final sigma random");
	t_array_init(&input, 128);
	t_array_init(&output, 128);
	t_array_init(&expected, 128);
	unicode_casemap_init_lowercase_final_sigma(&map);
	for (i = 0; i < 2000 && !test_has_failed(); i++) {
		array_clear(&input);
		count = i_rand_limit(80);
		for (j = 0; j < count; j++) {
			if (i_rand_limit(40) == 0) {
				/* Around the limit of case-ignorable code
				   points after a sigma */
				cp = 0x0301;
				for (k = i_rand_minmax(29, 34); k > 0; k--)
					array_push_back(&input, &cp);
			} else if (i_rand_limit(4) == 0) {
				cp = 0x0301;
				array_push_back(&input, &cp);
			} else {
				array_push_back(&input,
					&pool[i_rand_limit(N_ELEMENTS(pool))]);
			}
		}
		cps = array_get(&input, &count);

		array_clear(&expected);
		for (j = 0; j < count; j++) {
			if (cps[j] == 0x03a3 &&
			    test_final_sigma_ref_is_final(cps, count, j)) {
				cp = 0x03c2;
				array_push_back(&expected, &cp);
				continue;
			}
			map_len = unicode_code_point_data_get_lowercase_mapping(
				unicode_code_point_get_data(cps[j]), &map_cps);
			if (map_len == 0)
				array_push_back(&expected, &cps[j]);
			else
				array_append(&expected, map_cps, map_len);
		}

		test_casemap_run(&map, cps, count, i_rand_minmax(1, 40),
				 i_rand_limit(2) == 0, &output);
		test_assert_idx(test_arrays_equal(&output, &expected), i);
	}
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
	test_casemap_final_sigma();
	test_casemap_final_sigma_random();
}
