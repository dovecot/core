#ifndef __AUTH_CONNECTION_H
#define __AUTH_CONNECTION_H

struct client;
struct auth_request;

/* reply is NULL if auth connection died */
typedef void auth_callback_t(struct auth_request *request,
			     struct auth_login_reply *reply,
			     const unsigned char *data, struct client *client);

struct auth_connection {
	struct auth_connection *next;

	char *path;
	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	unsigned int pid;
	enum auth_mech available_auth_mechs;
        struct auth_login_reply reply;

        struct hash_table *requests;

	unsigned int handshake_received:1;
	unsigned int reply_received:1;
};

struct auth_request {
        enum auth_mech mech;
        struct auth_connection *conn;

	unsigned int id;

	auth_callback_t *callback;
	void *context;

	unsigned int init_sent:1;
};

extern enum auth_mech available_auth_mechs;

int auth_init_request(enum auth_mech mech, auth_callback_t *callback,
		      void *context, const char **error);

void auth_continue_request(struct auth_request *request,
			   const unsigned char *data, size_t data_size);

void auth_abort_request(struct auth_request *request);

void auth_connection_init(void);
void auth_connection_deinit(void);

#endif
