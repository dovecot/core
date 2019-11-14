#ifndef TEST_STATS_COMMON
#define TEST_STATS_COMMON 1

#include "stats-common.h"
#include "event-filter.h"
#include "istream.h"
#include "settings-parser.h"
#include "str.h"
#include "test-common.h"
#include "lib-event-private.h"
#include "stats-dist.h"
#include "stats-event-category.h"
#include "stats-metrics.h"

extern struct event_category test_category;
extern struct event_category child_test_category;
extern pool_t test_pool;

bool test_stats_callback(struct event *event,
			 enum event_callback_type type ATTR_UNUSED,
			 struct failure_context *ctx, const char *fmt ATTR_UNUSED,
			 va_list args ATTR_UNUSED);

void test_init(const char *settings_blob);
void test_deinit(void);

void test_event_send(struct event *event);

enum stats_dist_field {
        STATS_DIST_COUNT,
        STATS_DIST_SUM,
};

uint64_t get_stats_dist_field(const char *metric_name, enum stats_dist_field field);

#endif
