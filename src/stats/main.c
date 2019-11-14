/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "stats-common.h"
#include "restrict-access.h"
#include "ioloop.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "stats-settings.h"
#include "stats-event-category.h"
#include "stats-metrics.h"
#include "stats-service.h"
#include "client-writer.h"
#include "client-reader.h"
#include "client-http.h"

const struct stats_settings *stats_settings;
struct stats_metrics *stats_metrics;
time_t stats_startup_time;

static bool client_is_writer(const char *path)
{
	const char *name, *suffix;

	name = strrchr(path, '/');
	if (name == NULL)
		name = path;
	else
		name++;

	suffix = strrchr(name, '-');
	if (suffix == NULL)
		suffix = name;
	else
		suffix++;

	return strcmp(suffix, "writer") == 0;
}

static void client_connected(struct master_service_connection *conn)
{
	if (strcmp(conn->name, "http") == 0)
		client_http_create(conn);
	else if (client_is_writer(conn->name))
		client_writer_create(conn->fd);
	else
		client_reader_create(conn->fd);
	master_service_client_connection_accept(conn);
}

static void stats_die(void)
{
	/* just wait for existing stats clients to disconnect from us */
}

static void main_preinit(void)
{
	restrict_access_by_env(RESTRICT_ACCESS_FLAG_ALLOW_ROOT, NULL);
	restrict_access_allow_coredumps(TRUE);
}

static void main_init(void)
{
	void **sets = master_service_settings_get_others(master_service);
	stats_settings = sets[0];

	stats_startup_time = ioloop_time;
	stats_metrics = stats_metrics_init(stats_settings);
	stats_event_categories_init();
	client_readers_init();
	client_writers_init();
	client_http_init();
	stats_services_init();
}

static void main_deinit(void)
{
	stats_services_deinit();
	client_readers_deinit();
	client_writers_deinit();
	client_http_deinit();
	stats_event_categories_deinit();
	stats_metrics_deinit(&stats_metrics);
}

int main(int argc, char *argv[])
{
	const struct setting_parser_info *set_roots[] = {
		&stats_setting_parser_info,
		NULL
	};
	const enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_USE_SSL_SETTINGS |
		MASTER_SERVICE_FLAG_NO_SSL_INIT |
		MASTER_SERVICE_FLAG_DONT_SEND_STATS |
		MASTER_SERVICE_FLAG_NO_IDLE_DIE |
		MASTER_SERVICE_FLAG_UPDATE_PROCTITLE;
	const char *error;

	master_service = master_service_init("stats", service_flags,
					     &argc, &argv, "");
	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;
	if (master_service_settings_read_simple(master_service, set_roots,
						&error) < 0)
		i_fatal("Error reading configuration: %s", error);
	master_service_init_log(master_service, "stats: ");
	master_service_set_die_callback(master_service, stats_die);

	main_preinit();

	main_init();
	master_service_init_finish(master_service);
	master_service_run(master_service, client_connected);
	main_deinit();
	master_service_deinit(&master_service);
        return 0;
}
