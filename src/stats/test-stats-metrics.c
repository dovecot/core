/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "test-stats-common.h"
#include "array.h"

bool test_stats_callback(struct event *event,
			 enum event_callback_type type ATTR_UNUSED,
			 struct failure_context *ctx, const char *fmt ATTR_UNUSED,
			 va_list args ATTR_UNUSED)
{
	if (metrics != NULL) {
		stats_metrics_event(metrics, event, ctx);
		struct event_filter *filter = stats_metrics_get_event_filter(metrics);
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
	struct event_filter *filter = stats_metrics_get_event_filter(metrics);
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
		test_assert(metric->group_by != NULL);
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
	struct stats_metrics_iter *iter = stats_metrics_iterate_init(metrics);
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

int main(void) {
	void (*const test_functions[])(void) = {
		test_stats_metrics,
		test_stats_metrics_filter,
		test_stats_metrics_group_by_discrete,
		NULL
	};

	int ret = test_run(test_functions);

	return ret;
}
