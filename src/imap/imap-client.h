#ifndef IMAP_CLIENT_H
#define IMAP_CLIENT_H

#include "imap-commands.h"
#include "message-size.h"

#define CLIENT_COMMAND_QUEUE_MAX_SIZE 4
/* Maximum number of CONTEXT=SEARCH UPDATEs. Clients probably won't need more
   than a few, so this is mainly to avoid more or less accidental pointless
   resource usage. */
#define CLIENT_MAX_SEARCH_UPDATES 10

struct client;
struct mail_storage;
struct imap_parser;
struct imap_arg;

struct mailbox_keywords {
	/* All keyword names. The array itself exists in mail_index.
	   Keywords are currently only appended, they're never removed. */
	const ARRAY_TYPE(keywords) *names;
	/* Number of keywords announced to client via FLAGS/PERMANENTFLAGS.
	   This relies on keywords not being removed while mailbox is
	   selected. */
	unsigned int announce_count;
};

struct imap_search_update {
	char *tag;
	struct mail_search_result *result;
	bool return_uids;
};

enum client_command_state {
	/* Waiting for more input */
	CLIENT_COMMAND_STATE_WAIT_INPUT,
	/* Waiting to be able to send more output */
	CLIENT_COMMAND_STATE_WAIT_OUTPUT,
	/* Wait for other commands to finish execution */
	CLIENT_COMMAND_STATE_WAIT_UNAMBIGUITY,
	/* Waiting for other commands to finish so we can sync */
	CLIENT_COMMAND_STATE_WAIT_SYNC,
	/* Command is finished */
	CLIENT_COMMAND_STATE_DONE
};

struct client_command_context {
	struct client_command_context *prev, *next;
	struct client *client;

	pool_t pool;
	/* IMAP command tag */
	const char *tag;
	/* Name of this command */
	const char *name;
	/* Parameters for this command. These are generated from parsed IMAP
	   arguments, so they may not be exactly the same as how client sent
	   them. */
	const char *args;
	enum command_flags cmd_flags;

	command_func_t *func;
	void *context;

	/* Module-specific contexts. */
	ARRAY_DEFINE(module_contexts, union imap_module_context *);

	struct imap_parser *parser;
	enum client_command_state state;

	struct client_sync_context *sync;

	unsigned int uid:1; /* used UID command */
	unsigned int cancel:1; /* command is wanted to be cancelled */
	unsigned int param_error:1;
	unsigned int search_save_result:1; /* search result is being updated */
	unsigned int search_save_result_used:1; /* command uses search save */
	unsigned int temp_executed:1; /* temporary execution state tracking */
};

struct partial_fetch_cache {
	unsigned int select_counter;
	unsigned int uid;

	uoff_t physical_start;
	bool cr_skipped;
	struct message_size pos;
};

struct imap_client_vfuncs {
	void (*destroy)(struct client *client, const char *reason);
};

struct client {
	struct client *prev, *next;

	struct imap_client_vfuncs v;
	const char *session_id;

	int fd_in, fd_out;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct timeout *to_idle, *to_idle_output;

	pool_t pool;
	struct mail_storage_service_user *service_user;
        const struct imap_settings *set;
	string_t *capability_string;

        struct mail_user *user;
	struct mailbox *mailbox;
        struct mailbox_keywords keywords;
	unsigned int select_counter; /* increased when mailbox is changed */
	unsigned int sync_counter;
	uint32_t messages_count, recent_count, uidvalidity;
	enum mailbox_feature enabled_features;

	time_t last_input, last_output;
	unsigned int bad_counter;

	/* one parser is kept here to be used for new commands */
	struct imap_parser *free_parser;
	/* command_pool is cleared when the command queue gets empty */
	pool_t command_pool;
	/* New commands are always prepended to the queue */
	struct client_command_context *command_queue;
	unsigned int command_queue_size;

	uint64_t sync_last_full_modseq;
	uint64_t highest_fetch_modseq;

	struct partial_fetch_cache last_partial;

	/* SEARCHRES extension: Last saved SEARCH result */
	ARRAY_TYPE(seq_range) search_saved_uidset;
	/* SEARCH=CONTEXT extension: Searches that get updated */
	ARRAY_DEFINE(search_updates, struct imap_search_update);

	/* client input/output is locked by this command */
	struct client_command_context *input_lock;
	struct client_command_context *output_lock;
	/* command changing the mailbox */
	struct client_command_context *mailbox_change_lock;

	/* Module-specific contexts. */
	ARRAY_DEFINE(module_contexts, union imap_module_context *);

	/* syncing marks this TRUE when it sees \Deleted flags. this is by
	   EXPUNGE for Outlook-workaround. */
	unsigned int sync_seen_deletes:1;
	unsigned int sync_seen_expunges:1;
	unsigned int disconnected:1;
	unsigned int destroyed:1;
	unsigned int handling_input:1;
	unsigned int syncing:1;
	unsigned int id_logged:1;
	unsigned int mailbox_examined:1;
	unsigned int anvil_sent:1;
	unsigned int tls_compression:1;
	unsigned int input_skip_line:1; /* skip all the data until we've
					   found a new line */
	unsigned int modseqs_sent_since_sync:1;
};

struct imap_module_register {
	unsigned int id;
};

union imap_module_context {
	struct imap_client_vfuncs super;
	struct imap_module_register *reg;
};
extern struct imap_module_register imap_module_register;

extern struct client *imap_clients;
extern unsigned int imap_client_count;

/* Create new client with specified input/output handles. socket specifies
   if the handle is a socket. */
struct client *client_create(int fd_in, int fd_out, const char *session_id,
			     struct mail_user *user,
			     struct mail_storage_service_user *service_user,
			     const struct imap_settings *set);
void client_destroy(struct client *client, const char *reason);

/* Disconnect client connection */
void client_disconnect(struct client *client, const char *reason);
void client_disconnect_with_error(struct client *client, const char *msg);

/* Send a line of data to client. Returns 1 if ok, 0 if buffer is getting full,
   -1 if error */
int client_send_line(struct client *client, const char *data);
/* Send line of data to client, prefixed with client->tag. You need to prefix
   the data with "OK ", "NO " or "BAD ". */
void client_send_tagline(struct client_command_context *cmd, const char *data);

/* Send a BAD command reply to client via client_send_tagline(). If there have
   been too many command errors, the client is disconnected. msg may be NULL,
   in which case the error is looked up from imap_parser. */
void client_send_command_error(struct client_command_context *cmd,
			       const char *msg);

/* Read a number of arguments. Returns TRUE if everything was read or
   FALSE if either needs more data or error occurred. */
bool client_read_args(struct client_command_context *cmd, unsigned int count,
		      unsigned int flags, const struct imap_arg **args_r);
/* Reads a number of string arguments. ... is a list of pointers where to
   store the arguments. */
bool client_read_string_args(struct client_command_context *cmd,
			     unsigned int count, ...);

/* SEARCHRES extension: Call if $ is being used/updated, returns TRUE if we
   have to wait for an existing SEARCH SAVE to finish. */
bool client_handle_search_save_ambiguity(struct client_command_context *cmd);

int client_enable(struct client *client, enum mailbox_feature features);

struct imap_search_update *
client_search_update_lookup(struct client *client, const char *tag,
			    unsigned int *idx_r);
void client_search_updates_free(struct client *client);

void client_command_cancel(struct client_command_context **cmd);
void client_command_free(struct client_command_context **cmd);

bool client_handle_unfinished_cmd(struct client_command_context *cmd);
void client_continue_pending_input(struct client *client);

void client_input(struct client *client);
bool client_handle_input(struct client *client);
int client_output(struct client *client);

void clients_destroy_all(void);

#endif
