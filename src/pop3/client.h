#ifndef __CLIENT_H
#define __CLIENT_H

struct client;
struct mail_storage;

typedef void command_func_t(struct client *client);

struct client {
	int socket;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	command_func_t *cmd;
	void *cmd_context;

	struct mail_storage *storage;
	struct mailbox *mailbox;

	time_t last_input, last_output;
	unsigned int bad_counter;

	unsigned int messages_count;
	unsigned int deleted_count;
	uoff_t *message_sizes;
	uoff_t total_size;
	uoff_t deleted_size;
	uint32_t last_seen;

	unsigned char *deleted_bitmask;

	unsigned int deleted:1;
	unsigned int waiting_input:1;
};

/* Create new client with specified input/output handles. socket specifies
   if the handle is a socket. */
struct client *client_create(int hin, int hout, struct mail_storage *storage);
void client_destroy(struct client *client);

/* Disconnect client connection */
void client_disconnect(struct client *client);

/* Send a line of data to client */
int client_send_line(struct client *client, const char *fmt, ...)
	__attr_format__(2, 3);
void client_send_storage_error(struct client *client);

void clients_init(void);
void clients_deinit(void);

#endif
