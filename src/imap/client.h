#ifndef __CLIENT_H
#define __CLIENT_H

#include "imap-parser.h"
#include "mail-storage.h"

typedef struct _Client Client;

typedef int (*ClientCommandFunc) (Client *client);

struct _Client {
	int socket;
	IO io;
	IOBuffer *inbuf, *outbuf;

	MailStorage *storage;
	Mailbox *mailbox;

	time_t last_input;
	unsigned int bad_counter;

	ImapParser *parser;
	const char *cmd_tag; /* tag of command (allocated from parser pool), */
	const char *cmd_name; /* command name (allocated from parser pool) */
	ClientCommandFunc cmd_func;

	unsigned int cmd_error:1;
	unsigned int cmd_uid:1; /* used UID command */
	unsigned int inbuf_skip_line:1; /* skip all the data until we've
					   found a new line */
};

/* Create new client with specified input/output handles. socket specifies
   if the handle is a socket. */
Client *client_create(int hin, int hout, int socket, MailStorage *storage);
void client_destroy(Client *client);

/* Disconnect client connection */
void client_disconnect(Client *client);

/* Send a line of data to client */
void client_send_line(Client *client, const char *data);
/* Send line of data to client, prefixed with client->tag */
void client_send_tagline(Client *client, const char *data);

/* Send BAD command error to client. msg can be NULL. */
void client_send_command_error(Client *client, const char *msg);

/* Read a number of arguments. Returns TRUE if everything was read or
   FALSE if either needs more data or error occured. */
int client_read_args(Client *client, unsigned int count, unsigned int flags,
		     ImapArg **args);
/* Reads a number of string arguments. ... is a list of pointers where to
   store the arguments. */
int client_read_string_args(Client *client, unsigned int count, ...);

void clients_init(void);
void clients_deinit(void);

#endif
