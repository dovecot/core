#ifndef __CLIENT_H
#define __CLIENT_H

#include "commands.h"

#define CLIENT_COMMAND_QUEUE_MAX_SIZE 4

struct client;
struct mail_storage;
struct imap_parser;
struct imap_arg;

struct mailbox_keywords {
	pool_t pool; /* will be p_clear()ed when changed */

	ARRAY_DEFINE(keywords, const char *);
};

struct client_command_context {
	struct client_command_context *prev, *next;
	struct client *client;

	pool_t pool;
	const char *tag;
	const char *name;
	enum command_flags cmd_flags;

	command_func_t *func;
	void *context;

	struct imap_parser *parser;

	unsigned int uid:1; /* used UID command */
	unsigned int cancel:1; /* command is wanted to be cancelled */
	unsigned int param_error:1;
	unsigned int output_pending:1;
	unsigned int waiting_unambiguity:1;
};

struct client {
	int fd_in, fd_out;
	struct io *io;
	struct istream *input;
	struct ostream *output;

        struct mail_namespace *namespaces;
	struct mailbox *mailbox;
        struct mailbox_keywords keywords;
	unsigned int select_counter; /* increased when mailbox is changed */
	uint32_t messages_count, recent_count;

	time_t last_input, last_output;
	unsigned int bad_counter;

	/* one parser is kept here to be used for new commands */
	struct imap_parser *free_parser;
	/* command_pool is cleared when the command queue gets empty */
	pool_t command_pool;
	struct client_command_context *command_queue;
	unsigned int command_queue_size;

	/* client input/output is locked by this command */
	struct client_command_context *input_lock;
	struct client_command_context *output_lock;

	unsigned int disconnected:1;
	unsigned int destroyed:1;
	unsigned int handling_input:1;
	unsigned int idling:1;
	unsigned int syncing:1;
	unsigned int input_skip_line:1; /* skip all the data until we've
					   found a new line */
};

/* Create new client with specified input/output handles. socket specifies
   if the handle is a socket. */
struct client *client_create(int fd_in, int fd_out,
			     struct mail_namespace *namespaces);
void client_destroy(struct client *client, const char *reason);

/* Disconnect client connection */
void client_disconnect(struct client *client, const char *reason);
void client_disconnect_with_error(struct client *client, const char *msg);

/* Send a line of data to client. Returns 1 if ok, 0 if buffer is getting full,
   -1 if error */
int client_send_line(struct client *client, const char *data);
/* Send line of data to client, prefixed with client->tag */
void client_send_tagline(struct client_command_context *cmd, const char *data);

/* Send BAD command error to client. msg can be NULL. */
void client_send_command_error(struct client_command_context *cmd,
			       const char *msg);

/* Read a number of arguments. Returns TRUE if everything was read or
   FALSE if either needs more data or error occurred. */
bool client_read_args(struct client_command_context *cmd, unsigned int count,
		      unsigned int flags, struct imap_arg **args);
/* Reads a number of string arguments. ... is a list of pointers where to
   store the arguments. */
bool client_read_string_args(struct client_command_context *cmd,
			     unsigned int count, ...);

void clients_init(void);
void clients_deinit(void);

void client_command_cancel(struct client_command_context *cmd);
void client_command_free(struct client_command_context *cmd);

void client_continue_pending_input(struct client *client);

void _client_input(struct client *client);
int _client_output(struct client *client);

#endif
