/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "test-stats-common.h"
#include "array.h"

bool test_stats_callback(struct event *event,
			 enum event_callback_type type ATTR_UNUSED,
			 struct failure_context *ctx, const char *fmt ATTR_UNUSED,
			 va_list args ATTR_UNUSED)
{
	if (stats_metrics != NULL) {
		stats_metrics_event(stats_metrics, event, ctx);
		struct event_filter *filter =
			stats_metrics_get_event_filter(stats_metrics);
		return !event_filter_match(filter, event, ctx);
	}
	return TRUE;
}

static const char *settings_blob_1 =
"metric=test\n"
"metric/test/name=test\n"
"metric/test/event_name=test\n"
"\n";

static void test_stats_metrics(void)
{
	test_begin("stats metrics (event counting)");

	/* register some stats */
	test_init(settings_blob_1);

	/* push event in */
	struct event *event = event_create(NULL);
	event_add_category(event, &test_category);
	event_set_name(event, "test");
	test_event_send(event);
	event_unref(&event);

	test_assert(get_stats_dist_field("test", STATS_DIST_COUNT) == 1);
	test_assert(get_stats_dist_field("test", STATS_DIST_SUM) > 0);

	test_deinit();
	test_end();
}

static const char *settings_blob_2 =
"metric=test\n"
"metric/test/name=test\n"
"metric/test/event_name=test\n"
"metric/test/filter=\n"
"metric/test/filter/test_field=value\n"
"\n";

static void test_stats_metrics_filter(void)
{
	test_begin("stats metrics (filter)");

	test_init(settings_blob_2);

	/* check filter */
	struct event_filter *filter =
		stats_metrics_get_event_filter(stats_metrics);
	string_t *str_filter = t_str_new(64);
	event_filter_export(filter, str_filter);
	test_assert_strcmp("ntest	ftest_field	value	",
			   str_c(str_filter));

	/* send event */
	struct event *event = event_create(NULL);
	event_add_category(event, &test_category);
	event_set_name(event, "test");
	event_add_str(event, "test_field", "value");
	test_event_send(event);
	event_unref(&event);

	test_assert(get_stats_dist_field("test", STATS_DIST_COUNT) == 1);
	test_assert(get_stats_dist_field("test", STATS_DIST_SUM) > 0);

	/* send another event */
	event = event_create(NULL);
	event_add_category(event, &test_category);
	event_set_name(event, "test");
	event_add_str(event, "test_field", "nother value");
	e_debug(event, "test");
	event_unref(&event);

	test_assert(get_stats_dist_field("test", STATS_DIST_COUNT) == 1);
	test_assert(get_stats_dist_field("test", STATS_DIST_SUM) > 0);

	test_deinit();
	test_end();
}

static void test_stats_metrics_group_by_check_one(const struct metric *metric,
						  const char *sub_name,
						  unsigned int total_count,
						  unsigned int submetric_count,
						  unsigned int group_by_count,
						  enum stats_metric_group_by_func group_by_func,
						  const char *group_by_field,
						  enum metric_value_type value_type)
{
	test_assert_strcmp(metric->name, "test");

	if (sub_name != NULL)
		test_assert_strcmp(metric->sub_name, sub_name);
	else
		test_assert(metric->sub_name == NULL);

	test_assert(stats_dist_get_count(metric->duration_stats) == total_count);

	if (submetric_count > 0) {
		test_assert(array_is_created(&metric->sub_metrics));
		test_assert(array_count(&metric->sub_metrics) == submetric_count);
	} else {
		test_assert(!array_is_created(&metric->sub_metrics));
	}

	if (group_by_count > 0) {
		test_assert(metric->group_by_count == group_by_count);
		i_assert(metric->group_by != NULL);
		test_assert(metric->group_by[0].func == group_by_func);
		test_assert_strcmp(metric->group_by[0].field, group_by_field);
	} else {
		test_assert(metric->group_by_count == 0);
		test_assert(metric->group_by == NULL);
	}

	test_assert(metric->group_value.type == value_type);
}

#define DISCRETE_TEST_VAL_COUNT	3
struct discrete_test {
	const char *settings_blob;
	unsigned int num_values;
	const char *values_first[DISCRETE_TEST_VAL_COUNT];
	const char *values_second[DISCRETE_TEST_VAL_COUNT];
};

static const struct discrete_test discrete_tests[] = {
	{
		"test_name sub_name",
		3,
		{ "eta", "kappa", "nu", },
		{ "upsilon", "pi", "epsilon", },
	},
	{
		"test_name:discrete sub_name:discrete",
		3,
		{ "apple", "bannana", "orange", },
		{ "pie", "yoghurt", "cobbler", },
	},
	{
		"test_name sub_name:discrete",
		3,
		{ "apollo", "gaia", "hermes", },
		{ "thor", "odin", "loki", },
	},
};

static void test_stats_metrics_group_by_discrete_real(const struct discrete_test *test)
{
	struct event *event;
	unsigned int i, j;

	test_begin(t_strdup_printf("stats metrics (discrete group by) - %s",
				   test->settings_blob));

	test_init(t_strdup_printf("metric=test\n"
				  "metric/test/name=test\n"
				  "metric/test/event_name=test\n"
				  "metric/test/group_by=%s\n"
				  "\n", test->settings_blob));

	for (i = 0; i < test->num_values; i++) {
		for (j = 0; j < test->num_values; j++) {
			event = event_create(NULL);
			event_add_category(event, &test_category);
			event_set_name(event, "test");
			event_add_str(event, "test_name", test->values_first[i]);
			event_add_str(event, "sub_name", test->values_second[j]);
			test_event_send(event);
			event_unref(&event);
		}
	}

	/* check total number of events */
	test_assert(get_stats_dist_field("test", STATS_DIST_COUNT) == test->num_values * test->num_values);

	/* analyze the structure */
	struct stats_metrics_iter *iter = stats_metrics_iterate_init(stats_metrics);
	const struct metric *root_metric = stats_metrics_iterate(iter);
	stats_metrics_iterate_deinit(&iter);

	test_stats_metrics_group_by_check_one(root_metric,
					      NULL,
					      test->num_values * test->num_values,
					      test->num_values,
					      2, STATS_METRIC_GROUPBY_DISCRETE,
					      "test_name", 0);

	struct metric *const *first = array_idx(&root_metric->sub_metrics, 0);

	/* examime each sub-metric */
	for (i = 0; i < test->num_values; i++) {
		test_stats_metrics_group_by_check_one(first[i],
						      test->values_first[i],
						      test->num_values,
						      test->num_values,
						      1, STATS_METRIC_GROUPBY_DISCRETE,
						      "sub_name",
						      METRIC_VALUE_TYPE_STR);

		struct metric *const *second = array_idx(&first[i]->sub_metrics, 0);

		/* examine each sub-sub-metric */
		for (j = 0; j < test->num_values; j++) {
			test_stats_metrics_group_by_check_one(second[j],
							      test->values_second[j],
							      1, 0, 0, 0, NULL,
							      METRIC_VALUE_TYPE_STR);
		}
	}

	test_deinit();
	test_end();
}

static void test_stats_metrics_group_by_discrete(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(discrete_tests); i++)
		test_stats_metrics_group_by_discrete_real(&discrete_tests[i]);
}

#define QUANTIZED_TEST_VAL_COUNT	15
struct quantized_test {
	const char *settings_blob;
	unsigned int num_inputs;
	intmax_t input_vals[QUANTIZED_TEST_VAL_COUNT];

	unsigned int num_sub_metrics;

	unsigned int num_ranges;
	struct {
		struct stats_metric_settings_bucket_range range;
		intmax_t count;
	} ranges[QUANTIZED_TEST_VAL_COUNT];
};

static const struct quantized_test quantized_tests[] = {
	{
		"linear:100:1000:100",
		13,
		{ 0, 50, 100, 101, 200, 201, 250, 301, 900, 901, 1000, 1001, 2000 },
		7,
		11,
		{ { { INTMAX_MIN, 100 }, 3 },
		  { { 100, 200 }, 2 },
		  { { 200, 300 }, 2 },
		  { { 300, 400 }, 1 },
		  { { 400, 500 }, 0 },
		  { { 500, 600 }, 0 },
		  { { 600, 700 }, 0 },
		  { { 700, 800 }, 0 },
		  { { 800, 900 }, 1 },
		  { { 900, 1000 }, 2 },
		  { { 1000, INTMAX_MAX }, 2 },
		}
	},
	{
		/* start at 0 */
		"exponential:0:6:10",
		12,
		{ 0, 5, 10, 11, 100, 101, 500, 1000, 1001, 1000000, 1000001, 2000000 },
		7,
		8,
		{ { { INTMAX_MIN, 1 }, 1 },
		  { { 1, 10 }, 2 },
		  { { 10, 100 }, 2 },
		  { { 100, 1000 }, 3 },
		  { { 1000, 10000 }, 1 },
		  { { 10000, 100000 }, 0 },
		  { { 100000, 1000000 }, 1 },
		  { { 1000000, INTMAX_MAX }, 2 },
		}
	},
	{
		/* start at 0 */
		"exponential:0:6:2",
		9,
		{ 0, 1, 2, 4, 5, 20, 64, 65, 100 },
		7,
		8,
		{ { { INTMAX_MIN, 1 }, 2 },
		  { { 1, 2 }, 1 },
		  { { 2, 4 }, 1 },
		  { { 4, 8 }, 1 },
		  { { 8, 16 }, 0 },
		  { { 16, 32 }, 1 },
		  { { 32, 64 }, 1 },
		  { { 64, INTMAX_MAX }, 2 },
		}
	},
	{
		/* start at >0 */
		"exponential:2:6:10",
		12,
		{ 0, 5, 10, 11, 100, 101, 500, 1000, 1001, 1000000, 1000001, 2000000 },
		5,
		6,
		{ { { INTMAX_MIN, 100 }, 5 },
		  { { 100, 1000 }, 3 },
		  { { 1000, 10000 }, 1 },
		  { { 10000, 100000 }, 0 },
		  { { 100000, 1000000 }, 1 },
		  { { 1000000, INTMAX_MAX }, 2 },
		}
	},
	{
		/* start at >0 */
		"exponential:2:6:2",
		9,
		{ 0, 1, 2, 4, 5, 20, 64, 65, 100 },
		5,
		6,
		{ { { INTMAX_MIN, 4 }, 4 },
		  { { 4, 8 }, 1 },
		  { { 8, 16 }, 0 },
		  { { 16, 32 }, 1 },
		  { { 32, 64 }, 1 },
		  { { 64, INTMAX_MAX }, 2 },
		}
	},
};

static void test_stats_metrics_group_by_quantized_real(const struct quantized_test *test)
{
	unsigned int i;

	test_begin(t_strdup_printf("stats metrics (quantized group by) - %s",
				   test->settings_blob));

	test_init(t_strdup_printf("metric=test\n"
				  "metric/test/name=test\n"
				  "metric/test/event_name=test\n"
				  "metric/test/group_by=test_name foobar:%s\n"
				  "\n", test->settings_blob));

	struct event *event;

	for (i = 0; i < test->num_inputs; i++) {
		event = event_create(NULL);
		event_add_category(event, &test_category);
		event_set_name(event, "test");
		event_add_str(event, "test_name", "alpha");
		event_add_int(event, "foobar", test->input_vals[i]);
		test_event_send(event);
		event_unref(&event);
	}

	/* check total number of events */
	test_assert(get_stats_dist_field("test", STATS_DIST_COUNT) == test->num_inputs);

	/* analyze the structure */
	struct stats_metrics_iter *iter = stats_metrics_iterate_init(stats_metrics);
	const struct metric *root_metric = stats_metrics_iterate(iter);
	stats_metrics_iterate_deinit(&iter);

	test_stats_metrics_group_by_check_one(root_metric, NULL, test->num_inputs,
					      1, 2, STATS_METRIC_GROUPBY_DISCRETE,
					      "test_name", 0);

	/* examine first level sub-metric */
	struct metric *const *first = array_idx(&root_metric->sub_metrics, 0);
	test_stats_metrics_group_by_check_one(first[0],
					      "alpha",
					      test->num_inputs,
					      test->num_sub_metrics,
					      1,
					      STATS_METRIC_GROUPBY_QUANTIZED,
					      "foobar",
					      METRIC_VALUE_TYPE_STR);

	/* check the ranges */
	test_assert(first[0]->group_by[0].num_ranges == test->num_ranges);
	for (i = 0; i < test->num_ranges; i++) {
		test_assert(first[0]->group_by[0].ranges[i].min == test->ranges[i].range.min);
		test_assert(first[0]->group_by[0].ranges[i].max == test->ranges[i].range.max);
	}

	/* examine second level sub-metrics */
	struct metric *const *second = array_idx(&first[0]->sub_metrics, 0);

	for (i = 0; i < test->num_sub_metrics; i++) {
		const char *sub_name;
		intmax_t range_idx;

		/* we check these first, before we use the value below */
		test_assert(second[i]->group_value.type == METRIC_VALUE_TYPE_BUCKET_INDEX);
		test_assert(second[i]->group_value.intmax < test->num_ranges);

		range_idx = second[i]->group_value.intmax;

		/* construct the expected sub-metric name */
		if (test->ranges[range_idx].range.min == INTMAX_MIN) {
			sub_name = t_strdup_printf("foobar_ninf_%jd",
						   test->ranges[range_idx].range.max);
		} else if (test->ranges[range_idx].range.max == INTMAX_MAX) {
			sub_name = t_strdup_printf("foobar_%jd_inf",
						   test->ranges[range_idx].range.min + 1);
		} else {
			sub_name = t_strdup_printf("foobar_%jd_%jd",
						   test->ranges[range_idx].range.min + 1,
						   test->ranges[range_idx].range.max);
		}

		test_stats_metrics_group_by_check_one(second[i],
						      sub_name,
						      test->ranges[second[i]->group_value.intmax].count,
						      0, 0, 0, NULL,
						      METRIC_VALUE_TYPE_BUCKET_INDEX);
	}

	test_deinit();
	test_end();
}

static void test_stats_metrics_group_by_quantized(void)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(quantized_tests); i++)
		test_stats_metrics_group_by_quantized_real(&quantized_tests[i]);
}

int main(void) {
	void (*const test_functions[])(void) = {
		test_stats_metrics,
		test_stats_metrics_filter,
		test_stats_metrics_group_by_discrete,
		test_stats_metrics_group_by_quantized,
		NULL
	};

	int ret = test_run(test_functions);

	return ret;
}
