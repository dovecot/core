/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

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

#define REPLICATOR_AUTH_SERVICE_NAME "replicator"
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
		doveadm_connection_create(queue, conn->fd);
	else
		(void)notify_connection_create(conn->fd, queue);
}

static void replication_add_users(struct replicator_queue *queue)
{
	struct auth_master_connection *auth_conn;
	struct auth_master_user_list_ctx *ctx;
	struct auth_user_info user_info;
	struct replicator_user *user;
	const char *path, *username;

	auth_conn = auth_master_init(set->auth_socket_path,
				     AUTH_MASTER_FLAG_NO_IDLE_TIMEOUT);

	memset(&user_info, 0, sizeof(user_info));
	user_info.service = REPLICATOR_AUTH_SERVICE_NAME;

	/* add all users into replication queue, so that we can start doing
	   full syncs for everyone whose state can't be found */
	ctx = auth_master_user_list_init(auth_conn, "", &user_info);
	while ((username = auth_master_user_list_next(ctx)) != NULL) {
		user = replicator_queue_add(queue, username,
					    REPLICATION_PRIORITY_NONE);
		user->last_update = 0;
	}
	if (auth_master_user_list_deinit(&ctx) < 0)
		i_error("listing users failed, can't replicate existing data");
	auth_master_deinit(&auth_conn);

	/* add updates from replicator db, if it exists */
	path = t_strconcat(service_set->state_dir, "/"REPLICATOR_DB_FNAME, NULL);
	(void)replicator_queue_import(queue, path);
}

static void ATTR_NULL(1)
replicator_dump_timeout(void *context ATTR_UNUSED)
{
	const char *path;

	path = t_strconcat(service_set->state_dir, "/"REPLICATOR_DB_FNAME, NULL);
	(void)replicator_queue_import(queue, path);
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
			      replicator_dump_timeout, (void *)NULL);
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
	master_service_init_log(master_service, "replicator: ");

	restrict_access_by_env(NULL, FALSE);
	restrict_access_allow_coredumps(TRUE);

	main_init();
	master_service_init_finish(master_service);
	master_service_run(master_service, client_connected);
	main_deinit();

	master_service_deinit(&master_service);
        return 0;
}
