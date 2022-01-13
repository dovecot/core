#ifndef MASTER_ADMIN_CLIENT_H
#define MASTER_ADMIN_CLIENT_H

#include "guid.h"

struct master_service_connection;
struct master_admin_client;

struct master_admin_client_callback {
	/* Handle a command sent to admin socket. Send the reply with
	   master_admin_client_send_reply(). The command can be processed
	   asynchronously. Returns TRUE if the command was handled, FALSE if
	   the command was unknown. */
	bool (*cmd)(struct master_admin_client *client,
		    const char *cmd, const char *const *args);

	/* Standard commands implemented by multiple processes: */

	/* Kick user's connections and return the number of connections kicked.
	   If conn_guid is not empty, only the specific connection is kicked. */
	unsigned int (*cmd_kick_user)(const char *user,
				      const guid_128_t conn_guid);
};

void master_admin_client_create(struct master_service_connection *master_conn);

/* Send reply to admin command from admin_client_command_t. */
void master_admin_client_send_reply(struct master_admin_client *client,
				    const char *reply);

/* Returns TRUE if service name points to admin socket. */
bool master_admin_client_can_accept(const char *name);

void master_admin_clients_init(const struct master_admin_client_callback *callbacks);

#endif
