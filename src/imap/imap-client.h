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
struct mail_storage_service_ctx;
struct lda_settings;
struct imap_parser;
struct imap_arg;
struct imap_urlauth_context;

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

	pool_t fetch_pool;
	struct imap_fetch_context *fetch_ctx;
};

enum client_command_state {
	/* Waiting for more input */
	CLIENT_COMMAND_STATE_WAIT_INPUT,
	/* Waiting to be able to send more output */
	CLIENT_COMMAND_STATE_WAIT_OUTPUT,
	/* Waiting for external interaction */
	CLIENT_COMMAND_STATE_WAIT_EXTERNAL,
	/* Wait for other commands to finish execution */
	CLIENT_COMMAND_STATE_WAIT_UNAMBIGUITY,
	/* Waiting for other commands to finish so we can sync */
	CLIENT_COMMAND_STATE_WAIT_SYNC,
	/* Command is finished */
	CLIENT_COMMAND_STATE_DONE
};

struct client_command_stats {
	/* time when command handling was started - typically this is after
	   reading all the parameters. */
	struct timeval start_time;
	/* time when command handling was last finished. this is before
	   mailbox syncing is done. */
	struct timeval last_run_timeval;
	/* io_loop_get_wait_usecs()'s value when the command was started */
	uint64_t start_ioloop_wait_usecs;
	/* how many usecs this command itself has spent running */
	uint64_t running_usecs;
	/* how many usecs this command itself has spent waiting for locks */
	uint64_t lock_wait_usecs;
	/* how many bytes of client input/output command has used */
	uint64_t bytes_in, bytes_out;
};

struct client_command_stats_start {
	struct timeval timeval;
	uint64_t lock_wait_usecs;
	uint64_t bytes_in, bytes_out;
};

struct client_command_context {
	struct client_command_context *prev, *next;
	struct client *client;
	struct event *event;

	pool_t pool;
	/* IMAP command tag */
	const char *tag;
	/* Name of this command */
	const char *name;
	/* Parameters for this command. These are generated from parsed IMAP
	   arguments, so they may not be exactly the same as how client sent
	   them. */
	const char *args;
	/* Parameters for this command generated with
	   imap_write_args_for_human(), so it's suitable for logging. */
	const char *human_args;
	enum command_flags cmd_flags;
	const char *tagline_reply;

	command_func_t *func;
	void *context;

	/* Module-specific contexts. */
	ARRAY(union imap_module_context *) module_contexts;

	struct imap_parser *parser;
	enum client_command_state state;
	struct client_command_stats stats;
	struct client_command_stats_start stats_start;

	struct imap_client_sync_context *sync;

	bool uid:1; /* used UID command */
	bool cancel:1; /* command is wanted to be cancelled */
	bool param_error:1;
	bool search_save_result:1; /* search result is being updated */
	bool search_save_result_used:1; /* command uses search save */
	bool temp_executed:1; /* temporary execution state tracking */
	bool tagline_sent:1;
	bool executing:1;
};

struct imap_client_vfuncs {
	/* Perform client initialization. This is called when client creation is
	   finished completely. Particulary, at this point the namespaces are
	   fully initialized, which is not the case for the client create hook.
	 */
	void (*init)(struct client *client);
	/* Destroy the client.*/
	void (*destroy)(struct client *client, const char *reason);

	/* Send a tagged response line. */
	void (*send_tagline)(struct client_command_context *cmd,
			     const char *data);
	/* Run "mailbox syncing". This can send any unsolicited untagged
	   replies. Returns 1 = done, 0 = wait for more space in output buffer,
	   -1 = failed. */
	int (*sync_notify_more)(struct imap_sync_context *ctx);

	/* Export client state into buffer. Returns 1 if ok, 0 if some state
	   couldn't be preserved, -1 if temporary internal error occurred. */
	int (*state_export)(struct client *client, bool internal,
			    buffer_t *dest, const char **error_r);
	/* Import a single block of client state from the given data. Returns
	   number of bytes successfully imported from the block, or 0 if state
	   is corrupted or contains unknown data (e.g. some plugin is no longer
	   loaded), -1 if temporary internal error occurred. */
	ssize_t (*state_import)(struct client *client, bool internal,
				const unsigned char *data, size_t size,
				const char **error_r);
};

struct client {
	struct client *prev, *next;

	struct imap_client_vfuncs v;
	struct event *event;
	const char *session_id;
	const char *const *userdb_fields; /* for internal session saving/restoring */

	int fd_in, fd_out;
	struct io *io;
	struct istream *input;
	struct ostream *output;
	struct timeout *to_idle, *to_idle_output, *to_delayed_input;

	pool_t pool;
	struct mail_storage_service_user *service_user;
	const struct imap_settings *set;
	const struct smtp_submit_settings *smtp_set;
	string_t *capability_string;
	const char *disconnect_reason;

        struct mail_user *user;
	struct mailbox *mailbox;
        struct mailbox_keywords keywords;
	unsigned int sync_counter;
	uint32_t messages_count, recent_count, uidvalidity;
	ARRAY(bool) enabled_features;

	time_t last_input, last_output;
	unsigned int bad_counter;

	/* one parser is kept here to be used for new commands */
	struct imap_parser *free_parser;
	/* command_pool is cleared when the command queue gets empty */
	pool_t command_pool;
	/* New commands are always prepended to the queue */
	struct client_command_context *command_queue;
	unsigned int command_queue_size;

	char *last_cmd_name;
	struct client_command_stats last_cmd_stats;

	uint64_t sync_last_full_modseq;
	uint64_t highest_fetch_modseq;
	ARRAY_TYPE(seq_range) fetch_failed_uids;

	/* For imap_logout_format statistics: */
	unsigned int fetch_hdr_count, fetch_body_count;
	uint64_t fetch_hdr_bytes, fetch_body_bytes;
	unsigned int deleted_count, expunged_count, trashed_count;
	unsigned int autoexpunged_count, append_count;

	/* SEARCHRES extension: Last saved SEARCH result */
	ARRAY_TYPE(seq_range) search_saved_uidset;
	/* SEARCH=CONTEXT extension: Searches that get updated */
	ARRAY(struct imap_search_update) search_updates;
	/* NOTIFY extension */
	struct imap_notify_context *notify_ctx;
	uint32_t notify_uidnext;

	/* client input/output is locked by this command */
	struct client_command_context *input_lock;
	struct client_command_context *output_cmd_lock;
	/* command changing the mailbox */
	struct client_command_context *mailbox_change_lock;

	/* IMAP URLAUTH context (RFC4467) */
	struct imap_urlauth_context *urlauth_ctx;	

	/* Module-specific contexts. */
	ARRAY(union imap_module_context *) module_contexts;

	/* syncing marks this TRUE when it sees \Deleted flags. this is by
	   EXPUNGE for Outlook-workaround. */
	bool sync_seen_deletes:1;
	bool logged_out:1;
	bool disconnected:1;
	bool hibernated:1;
	bool destroyed:1;
	bool handling_input:1;
	bool syncing:1;
	bool id_logged:1;
	bool mailbox_examined:1;
	bool anvil_sent:1;
	bool tls_compression:1;
	bool input_skip_line:1; /* skip all the data until we've
					   found a new line */
	bool modseqs_sent_since_sync:1;
	bool notify_immediate_expunges:1;
	bool notify_count_changes:1;
	bool notify_flag_changes:1;
	bool imap_metadata_enabled:1;
	bool nonpermanent_modseqs:1;
	bool state_import_bad_idle_done:1;
	bool state_import_idle_continue:1;
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

extern unsigned int imap_feature_condstore;
extern unsigned int imap_feature_qresync;

/* Create new client with specified input/output handles. socket specifies
   if the handle is a socket. */
struct client *client_create(int fd_in, int fd_out, const char *session_id,
			     struct event *event, struct mail_user *user,
			     struct mail_storage_service_user *service_user,
			     const struct imap_settings *set,
			     const struct smtp_submit_settings *smtp_set);
/* Finish creating the client. Returns 0 if ok, -1 if there's an error. */
int client_create_finish(struct client *client, const char **error_r);
void client_destroy(struct client *client, const char *reason) ATTR_NULL(2);

/* Disconnect client connection */
void client_disconnect(struct client *client, const char *reason);
void client_disconnect_with_error(struct client *client,
				  const char *client_error);

/* Add the given capability to the CAPABILITY reply. If imap_capability setting
   has an explicit capability, nothing is changed. */
void client_add_capability(struct client *client, const char *capability);

/* Send a line of data to client. */
void client_send_line(struct client *client, const char *data);
/* Send a line of data to client. Returns 1 if ok, 0 if buffer is getting full,
   -1 if error. This should be used when you're (potentially) sending a lot of
   lines to client. */
int client_send_line_next(struct client *client, const char *data);
/* Send line of data to client, prefixed with client->tag. You need to prefix
   the data with "OK ", "NO " or "BAD ". */
void client_send_tagline(struct client_command_context *cmd, const char *data);

/* Send a BAD command reply to client via client_send_tagline(). If there have
   been too many command errors, the client is disconnected. client_error may
   be NULL, in which case the error is looked up from imap_parser. */
void client_send_command_error(struct client_command_context *cmd,
			       const char *client_error);

/* Send a NO command reply with the default internal error message to client
   via client_send_tagline(). */
void client_send_internal_error(struct client_command_context *cmd);

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

void client_enable(struct client *client, unsigned int feature_idx);
/* Returns TRUE if the given feature is enabled */
bool client_has_enabled(struct client *client, unsigned int feature_idx);
/* Returns mailbox features that are currently enabled. */
enum mailbox_feature client_enabled_mailbox_features(struct client *client);
/* Returns all enabled features as strings. */
const char *const *client_enabled_features(struct client *client);

/* Send client processing to imap-idle process. If successful, returns TRUE
   and destroys the client. */
bool imap_client_hibernate(struct client **client);

struct imap_search_update *
client_search_update_lookup(struct client *client, const char *tag,
			    unsigned int *idx_r);
void client_search_updates_free(struct client *client);

struct client_command_context *client_command_alloc(struct client *client);
void client_command_init_finished(struct client_command_context *cmd);
void client_command_cancel(struct client_command_context **cmd);
void client_command_free(struct client_command_context **cmd);

bool client_handle_unfinished_cmd(struct client_command_context *cmd);
/* Handle any pending command input. This must be run at the end of all
   I/O callbacks after they've (potentially) finished some commands. */
void client_continue_pending_input(struct client *client);
void client_add_missing_io(struct client *client);
const char *client_stats(struct client *client);

void client_input(struct client *client);
bool client_handle_input(struct client *client);
int client_output(struct client *client);

void clients_init(void);
void clients_destroy_all(void);

#endif
