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

static const char *settings_blob_3 =
"metric=test\n"
"metric/test/name=test\n"
"metric/test/event_name=test\n"
"metric/test/group_by=test_name sub_name\n"
"\n";

static void test_stats_metrics_group_by(void)
{
	test_begin("stats metrics (group by)");

	test_init(settings_blob_3);

	struct event *event;

	event = event_create(NULL);
	event_add_category(event, &test_category);
	event_set_name(event, "test");
	event_add_str(event, "test_name", "alpha");
	event_add_str(event, "sub_name", "eta");
	test_event_send(event);
	event_unref(&event);

	event = event_create(NULL);
	event_add_category(event, &test_category);
	event_set_name(event, "test");
	event_add_str(event, "test_name", "phi");
	event_add_str(event, "sub_name", "beta");
	test_event_send(event);
	event_unref(&event);

	event = event_create(NULL);
	event_add_category(event, &test_category);
	event_set_name(event, "test");
	event_add_str(event, "test_name", "omega");
	event_add_str(event, "sub_name", "pi");
	test_event_send(event);
	event_unref(&event);

	/* we should have now three events */
	test_assert(get_stats_dist_field("test", STATS_DIST_COUNT) == 3);

	/* analyze the structure */
	const struct metric *root_metric, *leaf ATTR_UNUSED;
	struct metric *const *children;
	struct stats_metrics_iter *iter = stats_metrics_iterate_init(metrics);
	root_metric = stats_metrics_iterate(iter);
	stats_metrics_iterate_deinit(&iter);

	test_assert(array_is_created(&root_metric->sub_metrics));
	test_assert(array_count(&root_metric->sub_metrics) == 3);

	/* then look at each level */
	children = array_idx(&root_metric->sub_metrics, 0);
	test_assert_strcmp(children[0]->sub_name, "alpha");
	test_assert(stats_dist_get_count(children[0]->duration_stats) == 1);

	test_assert(array_is_created(&children[0]->sub_metrics));
	test_assert(array_count(&children[0]->sub_metrics) == 1);

	leaf = *array_idx(&children[0]->sub_metrics, 0);
	test_assert_strcmp(leaf->sub_name, "eta");
	test_assert(stats_dist_get_count(leaf->duration_stats) == 1);

	test_assert_strcmp(children[1]->sub_name, "phi");

	test_assert(array_is_created(&children[1]->sub_metrics));
	test_assert(array_count(&children[1]->sub_metrics) == 1);

	leaf = *array_idx(&children[1]->sub_metrics, 0);
	test_assert_strcmp(leaf->sub_name, "beta");
	test_assert(stats_dist_get_count(leaf->duration_stats) == 1);

	test_assert_strcmp(children[2]->sub_name, "omega");

	test_assert(array_is_created(&children[2]->sub_metrics));
	test_assert(array_count(&children[2]->sub_metrics) == 1);

	leaf = *array_idx(&children[2]->sub_metrics, 0);
	test_assert_strcmp(leaf->sub_name, "pi");
	test_assert(stats_dist_get_count(leaf->duration_stats) == 1);

	test_deinit();
	test_end();
}

int main(void) {
	void (*const test_functions[])(void) = {
		test_stats_metrics,
		test_stats_metrics_filter,
		test_stats_metrics_group_by,
		NULL
	};

	int ret = test_run(test_functions);

	return ret;
}
