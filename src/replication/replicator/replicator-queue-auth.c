/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "auth-master.h"
#include "replicator-queue-private.h"

#define REPLICATOR_AUTH_SERVICE_NAME "replicator"

void replicator_queue_add_auth_users(struct replicator_queue *queue,
				     const char *auth_socket_path,
				     const char *usermask, time_t last_update)
{
	struct auth_master_connection *auth_conn;
	struct auth_master_user_list_ctx *ctx;
	struct auth_user_info user_info;
	struct replicator_user *user;
	const char *username;

	e_debug(queue->event, "Add users from userdb with usermask '%s'",
		usermask);

	auth_conn = auth_master_init(auth_socket_path,
				     AUTH_MASTER_FLAG_NO_IDLE_TIMEOUT);

	i_zero(&user_info);
	user_info.service = REPLICATOR_AUTH_SERVICE_NAME;

	/* add all users into replication queue, so that we can start doing
	   full syncs for everyone whose state can't be found */
	ctx = auth_master_user_list_init(auth_conn, usermask, &user_info);
	while ((username = auth_master_user_list_next(ctx)) != NULL) {
		user = replicator_queue_get(queue, username);
		replicator_queue_update(queue, user, REPLICATION_PRIORITY_NONE);
		replicator_queue_add(queue, user);
		user->last_update = last_update;
	}
	if (auth_master_user_list_deinit(&ctx) < 0)
		e_error(queue->event,
			"listing users failed, can't replicate existing data");
	auth_master_deinit(&auth_conn);
}
