#ifndef AUTH_MASTER_PRIVATE_H
#define AUTH_MASTER_PRIVATE_H

#include "connection.h"
#include "auth-client-interface.h"
#include "auth-client-private.h"
#include "auth-master.h"
#include "master-interface.h"

#define AUTH_MASTER_IDLE_SECS 60

#define MAX_INBUF_SIZE 8192
#define MAX_OUTBUF_SIZE 1024

struct auth_master_connection {
	struct connection conn;
	struct connection_list *clist;
	struct event *event_parent, *event;

	char *auth_socket_path;
	enum auth_master_flags flags;

	struct ioloop *ioloop, *prev_ioloop;
	struct timeout *to;

	unsigned int id_counter;

	bool (*reply_callback)(const char *cmd, const char *const *args,
			       void *context);
	void *reply_context;

	unsigned int timeout_msecs;

	bool connected:1;
	bool sent_handshake:1;
	bool aborted:1;
};

/*
 * Request
 */

void auth_request_lookup_abort(struct auth_master_connection *conn);

int auth_master_run_cmd_pre(struct auth_master_connection *conn,
			    const char *cmd);
int auth_master_run_cmd_post(struct auth_master_connection *conn);
int auth_master_run_cmd(struct auth_master_connection *conn, const char *cmd);

unsigned int auth_master_next_request_id(struct auth_master_connection *conn);

/*
 * Connection
 */

void auth_master_set_io(struct auth_master_connection *conn);
void auth_master_unset_io(struct auth_master_connection *conn);

#endif
