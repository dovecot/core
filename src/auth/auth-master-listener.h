#ifndef AUTH_MASTER_LISTENER_H
#define AUTH_MASTER_LISTENER_H

enum listener_type {
	LISTENER_MASTER,
	LISTENER_CLIENT
};

struct auth_master_listener {
	struct auth *auth;
	unsigned int pid;

	ARRAY_DEFINE(sockets, struct auth_master_listener_socket *);
	ARRAY_DEFINE(masters, struct auth_master_connection *);
	ARRAY_DEFINE(clients, struct auth_client_connection *);

	struct timeout *to_clients;
};

struct auth_master_listener *auth_master_listener_create(struct auth *auth);
void auth_master_listener_destroy(struct auth_master_listener *listener);

void auth_master_listener_add(struct auth_master_listener *listener,
			      int fd, const char *path,
			      enum listener_type type);

void auth_master_listeners_send_handshake(void);
bool auth_master_listeners_masters_left(void);

void auth_master_listeners_init(void);
void auth_master_listeners_deinit(void);

#endif
