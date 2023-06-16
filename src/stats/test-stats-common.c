/* Copyright (c) 2019 Dovecot authors, see the included COPYING file */

#include "test-stats-common.h"
#include "settings.h"
#include <time.h>
#include <unistd.h>

struct event_category test_category = {
	.name = "test",
};

struct event_category child_test_category = {
	.name = "child",
	.parent = &test_category,
};

pool_t test_pool;
struct stats_metrics *stats_metrics = NULL;
time_t stats_startup_time;

static struct stats_settings *stats_set;
static struct settings_root *set_root;
static bool callback_added = FALSE;

static struct stats_settings *read_settings(const char *const settings[],
					    struct event **event_r)
{
	const char *error;

	set_root = settings_root_init();
	for (unsigned int i = 0; settings[i] != NULL; i++) {
		const char *key, *value;
		t_split_key_value_eq(settings[i], &key, &value);
		settings_root_override(set_root, key, value,
				       SETTINGS_OVERRIDE_TYPE_CODE);
	}
	struct stats_settings *set;
	struct event *event = event_create(NULL);
	event_set_ptr(event, SETTINGS_EVENT_ROOT, set_root);
	if (settings_get(event, &stats_setting_parser_info, 0, &set, &error) < 0)
		i_fatal("%s", error);
	*event_r = event;
	return set;
}

void test_init(const char *const settings_blob[])
{
	const char *error;

	if (!callback_added) {
		event_register_callback(test_stats_callback);
		callback_added = TRUE;
	}

	stats_event_categories_init();
	test_pool = pool_alloconly_create(MEMPOOL_GROWING"test pool", 2048);
	stats_startup_time = time(NULL);

	/* register test categories */
	stats_event_category_register(test_category.name, NULL);
	stats_event_category_register(child_test_category.name,
				      &test_category);

	struct event *event;
	stats_set = read_settings(settings_blob, &event);
	if (stats_metrics_init(event, stats_set, &stats_metrics, &error) < 0)
		i_fatal("%s", error);
	event_unref(&event);
}

void test_deinit(void)
{
	stats_metrics_deinit(&stats_metrics);
	settings_free(stats_set);
	settings_root_deinit(&set_root);
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
        struct stats_metrics_iter *iter =
		stats_metrics_iterate_init(stats_metrics);
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

