#ifndef STATS_COMMON_H
#define STATS_COMMON_H

#include "lib.h"
#include "stats-settings.h"

extern const struct master_service_ssl_settings *master_ssl_set;
extern struct stats_metrics *stats_metrics;
extern time_t stats_startup_time;

#endif
