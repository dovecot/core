/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "test-stats-common.h"

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

int main(void) {
	void (*const test_functions[])(void) = {
		test_stats_metrics,
		test_stats_metrics_filter,
		NULL
	};

	int ret = test_run(test_functions);

	return ret;
}
