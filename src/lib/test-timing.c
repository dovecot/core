/* Copyright (c) 2007-2016 Dovecot authors, see the included COPYING file */

#include "test-lib.h"
#include "timing.h"
#include "sort.h"

static void
test_timing_verify(const struct timing *t, const int64_t *input,
		   unsigned int input_size)
{
	uint64_t min = INT_MAX, max = 0, sum = 0;
	uint64_t *copy;
	unsigned int i;

	i_assert(input_size > 0);

	copy = i_new(uint64_t, input_size);
	for (i = 0; i < input_size; i++) {
		uint64_t value = input[i];

		if (min > value)
			min = value;
		if (max < value)
			max = value;
		sum += value;
		copy[i] = value;
	}
	i_qsort(copy, input_size, sizeof(*copy), uint64_cmp);

	test_assert_idx(timing_get_count(t) == input_size, input_size);
	test_assert_idx(timing_get_sum(t) == sum, input_size);
	test_assert_idx(timing_get_min(t)  == min, input_size);
	test_assert_idx(timing_get_max(t) == max, input_size);
	test_assert_idx(timing_get_avg(t) == (sum + input_size/2)/input_size, input_size);

	/* these aren't always fully accurate: */
	test_assert_idx(timing_get_median(t) >= copy[(input_size-1)/2] &&
			timing_get_median(t) <= copy[input_size/2],
			input_size);
	/* when we have 20 elements, [19] is the max, not the 95th %ile, so subtract 1 */
	test_assert_idx(timing_get_95th(t) == copy[input_size*95/100 - ((input_size%20) == 0 ? 1 : 0)],
			input_size);

	i_free(copy);
}

void test_timing(void)
{
	static int64_t test_input1[] = {
		20, 19, 18, 1, 2, 3, 4, 5, 6, 7, 8,
		9, 10, 11, 12, 13, 14, 15, 16, 17, -1
	};
	static int64_t test_input2[] = {
		20, 21, 19, 18, 1, 2, 3, 4, 5, 6, 7, 8,
		9, 10, 11, 12, 13, 14, 15, 16, 17, -1
	};
	static int64_t test_input3[] = {
		20, 21, 19, 18, 1, 2, 3, 4, 5, 6, 7, 8,
		9, 10, 11, 12, 13, 14, 15, 16, 17, 22, -1
	};
	static int64_t *test_inputs[] = {
		test_input1, test_input2, test_input3
	};
	struct timing *t;
	unsigned int i, j;

	for (i = 0; i < N_ELEMENTS(test_inputs); i++) {
		test_begin(t_strdup_printf("timings %u", i));
		t = timing_init();
		for (j = 0; test_inputs[i][j] >= 0; j++) {
			timing_add_usecs(t, test_inputs[i][j]);
			test_timing_verify(t, test_inputs[i], j+1);
		}
		timing_reset(t);
		test_assert(timing_get_count(t) == 0);
		test_assert(timing_get_max(t) == 0);
		timing_deinit(&t);
		test_end();
	}

	test_begin("timings large");
	t = timing_init();
	for (i = 0; i < 10000; i++)
		timing_add_usecs(t, i);
	test_assert(timing_get_count(t) == i);
	test_assert(timing_get_sum(t) == (i-1)*i/2);
	test_assert(timing_get_min(t) == 0);
	test_assert(timing_get_max(t) == i-1);
	test_assert(timing_get_avg(t) == i/2);
	/* just test that these work: */
	test_assert(timing_get_median(t) > 0 && timing_get_median(t) < i-1);
	test_assert(timing_get_95th(t) > 0 && timing_get_95th(t) < i-1);
	timing_deinit(&t);
	test_end();
}
