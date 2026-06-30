/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "stats-common.h"
#include "http-server.h"
#include "stats-service-private.h"

void stats_services_init(void)
{
	 stats_service_openmetrics_init();
}

void stats_services_deinit(void)
{
	/* Nothing yet */
}
