#ifndef __CLIENT_H
#define __CLIENT_H

#include "imap-parser.h"
#include "mail-storage.h"

struct client;

typedef int (*client_command_func_t)(struct client *client);

struct client {
	int socket;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	struct mail_storage *storage;
	struct mailbox *mailbox;

	time_t last_input;
	unsigned int bad_counter;

	struct imap_parser *parser;
	const char *cmd_tag; /* tag of command (allocated from parser pool), */
	const char *cmd_name; /* command name (allocated from parser pool) */
	client_command_func_t cmd_func;

	unsigned int cmd_error:1;
	unsigned int cmd_uid:1; /* used UID command */
	unsigned int sync_flags_send_uid:1;
	unsigned int rawlog:1;
	unsigned int input_skip_line:1; /* skip all the data until we've
					   found a new line */
};

/* Create new client with specified input/output handles. socket specifies
   if the handle is a socket. */
struct client *client_create(int hin, int hout, struct mail_storage *storage);
void client_destroy(struct client *client);

/* Disconnect client connection */
void client_disconnect(struct client *client);

/* Send a line of data to client */
void client_send_line(struct client *client, const char *data);
/* Send line of data to client, prefixed with client->tag */
void client_send_tagline(struct client *client, const char *data);

/* Send BAD command error to client. msg can be NULL. */
void client_send_command_error(struct client *client, const char *msg);

/* Read a number of arguments. Returns TRUE if everything was read or
   FALSE if either needs more data or error occured. */
int client_read_args(struct client *client, unsigned int count,
		     unsigned int flags, struct imap_arg **args);
/* Reads a number of string arguments. ... is a list of pointers where to
   store the arguments. */
int client_read_string_args(struct client *client, unsigned int count, ...);

void clients_init(void);
void clients_deinit(void);

#endif
