#ifndef __CLIENT_H
#define __CLIENT_H

struct client;
struct mail_storage;
struct imap_parser;
struct imap_arg;

typedef int command_func_t(struct client *client);

struct mailbox_keywords {
	pool_t pool; /* will be p_clear()ed when changed */

	char **keywords;
        unsigned int keywords_count;
};

struct client {
	int socket;
	struct io *io;
	struct istream *input;
	struct ostream *output;

        struct namespace *namespaces;
	struct mailbox *mailbox;
        struct mailbox_keywords keywords;
	unsigned int select_counter; /* increased when mailbox is changed */
	uint32_t messages_count, recent_count;

	time_t last_input, last_output;
	unsigned int bad_counter;

	struct imap_parser *parser;
	pool_t cmd_pool;
	const char *cmd_tag;
	const char *cmd_name;
	command_func_t *cmd_func;
	void *cmd_context;

	unsigned int command_pending:1;
	unsigned int input_pending:1;
	unsigned int output_pending:1;
	unsigned int cmd_uid:1; /* used UID command */
	unsigned int cmd_param_error:1;
	unsigned int rawlog:1;
	unsigned int input_skip_line:1; /* skip all the data until we've
					   found a new line */
};

/* Create new client with specified input/output handles. socket specifies
   if the handle is a socket. */
struct client *client_create(int hin, int hout, struct namespace *namespaces);
void client_destroy(struct client *client);

/* Disconnect client connection */
void client_disconnect(struct client *client);
void client_disconnect_with_error(struct client *client, const char *msg);

/* Send a line of data to client. Returns 1 if ok, 0 if buffer is getting full,
   -1 if error */
int client_send_line(struct client *client, const char *data);
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

void _client_reset_command(struct client *client);
void _client_input(void *context);
int _client_output(void *context);

#endif
