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

enum auth_master_request_state {
	AUTH_MASTER_REQUEST_STATE_SENT = 0,
	AUTH_MASTER_REQUEST_STATE_REPLIED,
	AUTH_MASTER_REQUEST_STATE_FINISHED,
	AUTH_MASTER_REQUEST_STATE_ABORTED,
};

struct auth_master_request_destroy_callback {
	auth_master_request_destroy_callback_t *callback;
	void *context;
};

struct auth_master_request {
	int refcount;
	pool_t pool;
	struct event *event;

	struct auth_master_connection *conn;
	struct auth_master_request *prev, *next;

	const char *cmd;
	const unsigned char *args;
	size_t args_size;

	unsigned int id;
	struct timeval create_stamp;

	enum auth_master_request_state state;

	auth_master_request_callback_t *callback;
	void *context;

	ARRAY(struct auth_master_request_destroy_callback) destroy_callbacks;

	bool sent:1;
	bool aborted:1;
	bool removed:1;
	bool in_callback:1;
};

struct auth_master_connection {
	struct connection conn;
	struct connection_list *clist;
	int refcount;
	pool_t pool;

	const char *auth_socket_path;
	enum auth_master_flags flags;

	struct timeout *to_connect, *to_idle, *to_request;
	struct ioloop *ioloop, *prev_ioloop;

	unsigned int id_counter;
	HASH_TABLE(void *, struct auth_master_request *) requests;
	struct auth_master_request *requests_head, *requests_tail;
	unsigned int requests_count;

	unsigned int timeout_msecs;

	pid_t auth_server_pid;

	bool in_timeout:1;
	bool connected:1;
	bool sent_handshake:1;
	bool waiting:1;
};

/*
 * Request
 */

unsigned int
auth_master_request_get_timeout_msecs(struct auth_master_request *req);

int auth_master_request_got_reply(struct auth_master_request **_req,
				  const char *reply, const char *const *args);
void auth_master_request_fail(struct auth_master_request **_req,
			      const char *reason);

/*
 * Connection
 */

void auth_master_check_idle(struct auth_master_connection *conn);
void auth_master_stop_idle(struct auth_master_connection *conn);

void auth_master_connection_update_timeout(struct auth_master_connection *conn);
void auth_master_connection_start_timeout(struct auth_master_connection *conn);

#endif
