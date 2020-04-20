/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "restrict-access.h"
#include "auth-master.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "notify-connection.h"
#include "doveadm-connection.h"
#include "replicator-brain.h"
#include "replicator-queue.h"
#include "replicator-settings.h"

#define REPLICATOR_DB_DUMP_INTERVAL_MSECS (1000*60*15)
/* if syncing fails, try again in 5 minutes */
#define REPLICATOR_FAILURE_RESYNC_INTERVAL_SECS (60*5)
#define REPLICATOR_DB_FNAME "replicator.db"

static struct replicator_queue *queue;
static struct replicator_brain *brain;
static const struct master_service_settings *service_set;
static const struct replicator_settings *set;
static struct timeout *to_dump;

static void client_connected(struct master_service_connection *conn)
{
	master_service_client_connection_accept(conn);
	if (strcmp(conn->name, "replicator-doveadm") == 0)
		doveadm_connection_create(brain, conn->fd);
	else
		(void)notify_connection_create(conn->fd, queue);
}

static void replication_add_users(struct replicator_queue *queue)
{
	const char *path;

	replicator_queue_add_auth_users(queue, set->auth_socket_path, "*", 0);

	/* add updates from replicator db, if it exists */
	path = t_strconcat(service_set->state_dir, "/"REPLICATOR_DB_FNAME, NULL);
	(void)replicator_queue_import(queue, path);
}

static void ATTR_NULL(1)
replicator_dump_timeout(void *context ATTR_UNUSED)
{
	const char *path;

	path = t_strconcat(service_set->state_dir, "/"REPLICATOR_DB_FNAME, NULL);
	(void)replicator_queue_export(queue, path);
}

static void main_init(void)
{
	void **sets;

	service_set = master_service_settings_get(master_service);
	sets = master_service_settings_get_others(master_service);
	set = sets[0];

	queue = replicator_queue_init(set->replication_full_sync_interval,
				      REPLICATOR_FAILURE_RESYNC_INTERVAL_SECS);
	replication_add_users(queue);
	to_dump = timeout_add(REPLICATOR_DB_DUMP_INTERVAL_MSECS,
			      replicator_dump_timeout, NULL);
	brain = replicator_brain_init(queue, set);
	doveadm_connections_init();
}

static void main_deinit(void)
{
	const char *path;

	doveadm_connections_deinit();
	notify_connections_destroy_all();
	replicator_brain_deinit(&brain);
	timeout_remove(&to_dump);
	path = t_strconcat(service_set->state_dir, "/"REPLICATOR_DB_FNAME, NULL);
	(void)replicator_queue_export(queue, path);
	replicator_queue_deinit(&queue);
}

int main(int argc, char *argv[])
{
	const struct setting_parser_info *set_roots[] = {
		&replicator_setting_parser_info,
		NULL
	};
	const enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_NO_IDLE_DIE;
	const char *error;

	master_service = master_service_init("replicator", service_flags,
					     &argc, &argv, "");
	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;

	if (master_service_settings_read_simple(master_service, set_roots,
						&error) < 0)
		i_fatal("Error reading configuration: %s", error);
	master_service_init_log(master_service);

	restrict_access_by_env(RESTRICT_ACCESS_FLAG_ALLOW_ROOT, NULL);
	restrict_access_allow_coredumps(TRUE);
	/* finish init before we get list of users from auth, because that
	   can take long enough for master process to kill us otherwise. */
	master_service_init_finish(master_service);

	main_init();
	master_service_run(master_service, client_connected);
	main_deinit();

	master_service_deinit(&master_service);
        return 0;
}
