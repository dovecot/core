#ifndef __CLIENT_H
#define __CLIENT_H

struct mail_storage;

struct client {
	int socket;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	struct mail_storage *storage;
	struct mailbox *mailbox;

	time_t last_input;
	unsigned int bad_counter;

	unsigned int messages_count;
	unsigned char *deleted_bitmask;

	unsigned int deleted:1;
};

/* Create new client with specified input/output handles. socket specifies
   if the handle is a socket. */
struct client *client_create(int hin, int hout, struct mailbox *mailbox);
void client_destroy(struct client *client);

/* Disconnect client connection */
void client_disconnect(struct client *client);

/* Send a line of data to client */
void client_send_line(struct client *client, const char *fmt, ...)
	__attr_format__(2, 3);

void clients_init(void);
void clients_deinit(void);

#endif
