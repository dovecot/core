#ifndef CLIENT_H
#define CLIENT_H

struct client;
struct mail_storage;

typedef void command_func_t(struct client *client);

struct client {
	int fd_in, fd_out;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	command_func_t *cmd;
	void *cmd_context;

	struct mail_namespace *namespaces, *inbox_ns;
	struct mailbox *mailbox;
	struct mailbox_transaction_context *trans;

	time_t last_input, last_output;
	unsigned int bad_counter;

	unsigned int uid_validity;
	unsigned int messages_count;
	unsigned int deleted_count;
	unsigned int expunged_count;
	uoff_t *message_sizes;
	uoff_t total_size;
	uoff_t deleted_size;
	uint32_t last_seen;

	uoff_t top_bytes;
	uoff_t retr_bytes;
	unsigned int top_count;
	unsigned int retr_count;

	uoff_t *byte_counter;
	uoff_t byte_counter_offset;

	unsigned char *deleted_bitmask;

	unsigned int disconnected:1;
	unsigned int deleted:1;
	unsigned int waiting_input:1;
};

/* Create new client with specified input/output handles. socket specifies
   if the handle is a socket. */
struct client *client_create(int fd_in, int fd_out,
			     struct mail_namespace *namespaces);
void client_destroy(struct client *client, const char *reason);

/* Disconnect client connection */
void client_disconnect(struct client *client, const char *reason);

/* Send a line of data to client */
int client_send_line(struct client *client, const char *fmt, ...)
	ATTR_FORMAT(2, 3);
void client_send_storage_error(struct client *client);

void clients_init(void);
void clients_deinit(void);

#endif
