#ifndef STATS_COMMON_H
#define STATS_COMMON_H

#include "lib.h"
#include "stats-settings.h"

extern const struct stats_settings *stats_settings;
extern struct stats_metrics *stats_metrics;
extern time_t stats_startup_time;

#endif
