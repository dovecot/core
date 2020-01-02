/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "test-stats-common.h"
#include <unistd.h>

struct event_category test_category = {
	.name = "test",
};

struct event_category child_test_category = {
	.name = "child",
	.parent = &test_category,
};

pool_t test_pool;
struct stats_metrics *metrics = NULL;

static bool callback_added = FALSE;

static struct stats_settings *read_settings(const char *settings)
{
	struct istream *is = test_istream_create(settings);
	const char *error;
	struct setting_parser_context *ctx =
		settings_parser_init(test_pool, &stats_setting_parser_info, 0);
	if (settings_parse_stream_read(ctx, is) < 0)
		i_fatal("Failed to parse settings: %s",
			settings_parser_get_error(ctx));
	if (!settings_parser_check(ctx, test_pool, &error))
		i_fatal("Failed to parse settings: %s",
			error);
	struct stats_settings *set = settings_parser_get(ctx);
	settings_parser_deinit(&ctx);
	i_stream_unref(&is);
	return set;
}

void test_init(const char *settings_blob)
{
	if (!callback_added) {
		event_register_callback(test_stats_callback);
		callback_added = TRUE;
	}

	stats_event_categories_init();
	test_pool = pool_alloconly_create(MEMPOOL_GROWING"test pool", 2048);

	/* register test categories */
	stats_event_category_register(test_category.name, NULL);
	stats_event_category_register(child_test_category.name,
				      &test_category);
	struct stats_settings *set = read_settings(settings_blob);
	metrics = stats_metrics_init(set);
}

void test_deinit(void)
{
	stats_metrics_deinit(&metrics);
	stats_event_categories_deinit();
	pool_unref(&test_pool);
}

void test_event_send(struct event *event)
{
        struct failure_context ctx = {
                .type = LOG_TYPE_DEBUG,
        };

	usleep(1); /* make sure duration>0 always */
        event_send(event, &ctx, "hello");
}

uint64_t get_stats_dist_field(const char *metric_name, enum stats_dist_field field)
{
        struct stats_metrics_iter *iter = stats_metrics_iterate_init(metrics);
        const struct metric *metric;
        while((metric = stats_metrics_iterate(iter)) != NULL)
                if (strcmp(metric->name, metric_name) == 0)
                        break;

        /* bug in test if not found */
        i_assert(metric != NULL);

        stats_metrics_iterate_deinit(&iter);

        switch(field) {
        case STATS_DIST_COUNT:
                return stats_dist_get_count(metric->duration_stats);
        case STATS_DIST_SUM:
                return stats_dist_get_sum(metric->duration_stats);
        default:
                i_unreached();
        }
}

