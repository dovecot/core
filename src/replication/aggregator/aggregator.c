/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "restrict-access.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "aggregator-settings.h"
#include "notify-connection.h"
#include "replicator-connection.h"

struct replicator_connection *replicator;
struct event *aggregator_event;

static struct event_category event_category_replication = {
	.name = "replication"
};

static void client_connected(struct master_service_connection *conn)
{
	const char *name;

	master_service_client_connection_accept(conn);
	if (conn->remote_port == 0)
		name = conn->name;
	else
		name = net_ipport2str(&conn->remote_ip, conn->remote_port);
	notify_connection_create(conn->fd, conn->fifo, name);
}

static void main_preinit(void)
{
	struct ip_addr *ips;
	unsigned int ips_count;
	const struct aggregator_settings *set;
	int ret;

	set = master_service_settings_get_root_set(master_service,
				&aggregator_setting_parser_info);

	aggregator_event = event_create(NULL);
	event_add_category(aggregator_event, &event_category_replication);

	if (set->replicator_port != 0) {
		ret = net_gethostbyname(set->replicator_host, &ips, &ips_count);
		if (ret != 0) {
			i_fatal("replicator_host: gethostbyname(%s) failed: %s",
				set->replicator_host, net_gethosterror(ret));
		}
		replicator = replicator_connection_create_inet(ips, ips_count,
				set->replicator_port,
				notify_connection_sync_callback);
	} else {
		replicator = replicator_connection_create_unix(set->replicator_host,
				notify_connection_sync_callback);
	}
}

int main(int argc, char *argv[])
{
	const struct setting_parser_info *set_roots[] = {
		&aggregator_setting_parser_info,
		NULL
	};
	const char *error;

	master_service = master_service_init("aggregator", 0, &argc, &argv, "");
	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;

	if (master_service_settings_read_simple(master_service, set_roots,
						&error) < 0)
		i_fatal("Error reading configuration: %s", error);
	master_service_init_log(master_service);

	main_preinit();

	restrict_access_by_env(RESTRICT_ACCESS_FLAG_ALLOW_ROOT, NULL);
	restrict_access_allow_coredumps(TRUE);
	master_service_init_finish(master_service);

	master_service_run(master_service, client_connected);

	notify_connections_destroy_all();
	replicator_connection_destroy(&replicator);
	event_unref(&aggregator_event);
	master_service_deinit(&master_service);
        return 0;
}
