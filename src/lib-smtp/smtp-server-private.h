#ifndef SMTP_SERVER_PRIVATE_H
#define SMTP_SERVER_PRIVATE_H

#include "connection.h"

#include "smtp-server.h"

#define SMTP_SERVER_COMMAND_POOL_MAX              (8 * 1024)

#define SMTP_SERVER_DEFAULT_MAX_COMMAND_LINE      (4 * 1024)
#define SMTP_SERVER_DEFAULT_MAX_BAD_COMMANDS      10
#define SMTP_SERVER_DEFAULT_MAX_SIZE_EXCESS_LIMIT (1024*1024)

#define SMTP_SERVER_DEFAULT_CAPABILITIES \
	(SMTP_CAPABILITY_SIZE | SMTP_CAPABILITY_ENHANCEDSTATUSCODES | \
		SMTP_CAPABILITY_8BITMIME | SMTP_CAPABILITY_CHUNKING)

struct smtp_server_cmd_hook;
struct smtp_server_reply;
struct smtp_server_command;
struct smtp_server_connection;

ARRAY_DEFINE_TYPE(smtp_server_reply, struct smtp_server_reply);
ARRAY_DEFINE_TYPE(smtp_server_cmd_hook, struct smtp_server_cmd_hook);

enum smtp_server_command_state {
	/* New command; callback to command start handler executing. */
	SMTP_SERVER_COMMAND_STATE_NEW = 0,
	/* This command is being processed; command data is fully read, but no
	   reply is yet submitted */
	SMTP_SERVER_COMMAND_STATE_PROCESSING,
	/* A reply is submitted for this command. If not all command data was
	   read by the handler, it is first skipped on the input. If this is a
	   multi-reply command (LMTP->DATA), not all replies may be submitted
	   yet. */
	SMTP_SERVER_COMMAND_STATE_SUBMITTED_REPLY,
	/* Request is ready for sending reply; a reply is submitted and the
	   command payload is fully read. If this is a multi-reply command
	   (LMTP->DATA), not all replies may be submitted yet. In that case the
	   command state goes back to PROCESSING once the all submitted replies
	   are sent. */
	SMTP_SERVER_COMMAND_STATE_READY_TO_REPLY,
	/* The reply for the command is sent */
	SMTP_SERVER_COMMAND_STATE_FINISHED,
	/* Request is aborted; still lingering due to references */
	SMTP_SERVER_COMMAND_STATE_ABORTED
};

struct smtp_server_command_hook {
	enum smtp_server_command_hook_type type;
	struct smtp_server_command_hook *prev, *next;

	smtp_server_cmd_func_t *func;
	void *context;
};

struct smtp_server_recipient_hook {
	enum smtp_server_recipient_hook_type type;
	struct smtp_server_recipient_hook *prev, *next;

	smtp_server_rcpt_func_t *func;
	void *context;
};

struct smtp_server_reply_content {
	unsigned int status;
	const char *enhanced_code;
	const char *status_prefix;

	string_t *text;
	size_t last_line;
};

struct smtp_server_reply {
	struct smtp_server_command *command;
	unsigned int index;
	struct event *event;

	/* replies may share content */
	struct smtp_server_reply_content *content;

	bool submitted:1;
	bool sent:1;
	bool forwarded:1;
};

struct smtp_server_command_reg {
	const char *name;
	enum smtp_server_command_flags flags;
	smtp_server_cmd_start_func_t *func;
};

struct smtp_server_command {
	struct smtp_server_cmd_ctx context;
	const struct smtp_server_command_reg *reg;
	int refcount;

	enum smtp_server_command_state state;

	struct smtp_server_command *prev, *next;

	struct smtp_server_command_hook *hooks_head, *hooks_tail;
	void *data;

	ARRAY_TYPE(smtp_server_reply) replies;
	unsigned int replies_expected;
	unsigned int replies_submitted;

	bool input_locked:1;
	bool input_captured:1;
	bool reply_early:1;
	bool destroying:1;
};

struct smtp_server_recipient_private {
	struct smtp_server_recipient rcpt;
	int refcount;

	struct smtp_server_recipient_hook *hooks_head, *hooks_tail;

	bool destroying:1;
};

struct smtp_server_state_data {
	enum smtp_server_state state;
	time_t timestamp;

	unsigned int pending_mail_cmds;
	unsigned int pending_rcpt_cmds, denied_rcpt_cmds;
	unsigned int pending_data_cmds;

	struct smtp_server_transaction *trans;
	struct istream *data_input, *data_chain_input;
	struct istream_chain *data_chain;
	unsigned int data_chunks;
	uoff_t data_size;

	bool data_failed:1;
};

struct smtp_server_connection {
	struct connection conn;
	struct smtp_server *server;
	pool_t pool;
	int refcount;
	struct event *event;

	struct smtp_server_settings set;

	ARRAY(struct smtp_capability_extra) extra_capabilities;
	ARRAY_TYPE(const_string) mail_param_extensions; /* NULL-terminated */
	ARRAY_TYPE(const_string) rcpt_param_extensions; /* NULL-terminated */

	const struct smtp_server_callbacks *callbacks;
	void *context;

	enum smtp_proxy_protocol proxy_proto;
	unsigned int proxy_ttl_plus_1;
	unsigned int proxy_timeout_secs;

	struct smtp_server_helo_data helo, *pending_helo;
	char *helo_domain, *username;

	struct timeout *to_idle;
	struct istream *raw_input;
	struct ostream *raw_output;
	struct ssl_iostream_context *ssl_ctx;
	struct ssl_iostream *ssl_iostream;
	struct smtp_command_parser *smtp_parser;

	struct smtp_server_command *command_queue_head, *command_queue_tail;
	unsigned int command_queue_count;
	unsigned int bad_counter;

	char *disconnect_reason;

	struct smtp_server_state_data state;

	struct smtp_server_stats stats;

	bool started:1;
	bool halted:1;
	bool ssl_start:1;
	bool ssl_secured:1;
	bool authenticated:1;
	bool created_from_streams:1;
	bool corked:1;
	bool disconnected:1;
	bool closing:1;
	bool closed:1;
	bool input_broken:1;
	bool input_locked:1;
	bool handling_input:1;
	bool rawlog_checked:1;
	bool rawlog_enabled:1;
};

struct smtp_server {
	pool_t pool;

	struct smtp_server_settings set;

	struct event *event;
	struct ssl_iostream_context *ssl_ctx;

	ARRAY(struct smtp_server_command_reg) commands_reg;

	struct connection_list *conn_list;

	bool commands_unsorted:1;
};

bool smtp_server_connection_pending_command_data(
	struct smtp_server_connection *conn);

/*
 * Reply
 */

void smtp_server_reply_free(struct smtp_server_command *cmd);

int smtp_server_reply_send(struct smtp_server_reply *resp);

const char *
smtp_server_reply_get_one_line(const struct smtp_server_reply *reply);
const char *
smtp_server_reply_get_message(const struct smtp_server_reply *reply);

void smtp_server_reply_add_to_event(const struct smtp_server_reply *reply,
				    struct event_passthrough *e);

/*
 * Command
 */

void smtp_server_commands_init(struct smtp_server *server);

void smtp_server_command_debug(struct smtp_server_cmd_ctx *cmd,
	const char *format, ...) ATTR_FORMAT(2, 3);

struct smtp_server_command *
smtp_server_command_new_invalid(struct smtp_server_connection *conn);
struct smtp_server_command *
smtp_server_command_new(struct smtp_server_connection *conn,
	const char *name, const char *params);
void smtp_server_command_ref(struct smtp_server_command *cmd);
bool smtp_server_command_unref(struct smtp_server_command **_cmd);
void smtp_server_command_abort(struct smtp_server_command **_cmd);

bool smtp_server_command_call_hooks(struct smtp_server_command **_cmd,
				    enum smtp_server_command_hook_type type,
				    bool remove);
void smtp_server_command_remove_hooks(struct smtp_server_command *cmd,
				      enum smtp_server_command_hook_type type);

void smtp_server_command_submit_reply(struct smtp_server_command *cmd);

int smtp_server_connection_flush(struct smtp_server_connection *conn);

void smtp_server_command_ready_to_reply(struct smtp_server_command *cmd);
void smtp_server_command_finished(struct smtp_server_command *cmd);

bool smtp_server_command_next_to_reply(struct smtp_server_command **_cmd);
bool smtp_server_command_completed(struct smtp_server_command **_cmd);

static inline bool
smtp_server_command_is_complete(struct smtp_server_command *cmd)
{
	struct smtp_server_connection *conn = cmd->context.conn;

	return (conn->input_broken || (cmd->next != NULL) || cmd->reply_early ||
		!smtp_server_connection_pending_command_data(conn));
}

void smtp_server_cmd_ehlo(struct smtp_server_cmd_ctx *cmd,
	const char *params);
void smtp_server_cmd_helo(struct smtp_server_cmd_ctx *cmd,
	const char *params);
void smtp_server_cmd_xclient(struct smtp_server_cmd_ctx *cmd,
	const char *params);

void smtp_server_cmd_starttls(struct smtp_server_cmd_ctx *cmd,
	const char *params);
void smtp_server_cmd_auth(struct smtp_server_cmd_ctx *cmd,
	const char *params);

void smtp_server_cmd_mail(struct smtp_server_cmd_ctx *cmd,
	const char *params);
void smtp_server_cmd_rcpt(struct smtp_server_cmd_ctx *cmd,
	const char *params);
void smtp_server_cmd_data(struct smtp_server_cmd_ctx *cmd,
	const char *params);
void smtp_server_cmd_bdat(struct smtp_server_cmd_ctx *cmd,
	const char *params);
void smtp_server_cmd_rset(struct smtp_server_cmd_ctx *cmd,
	const char *params);

void smtp_server_cmd_noop(struct smtp_server_cmd_ctx *cmd,
	const char *params);
void smtp_server_cmd_vrfy(struct smtp_server_cmd_ctx *cmd,
	const char *params);

void smtp_server_cmd_quit(struct smtp_server_cmd_ctx *cmd,
	const char *params);

/*
 * Connection
 */

typedef void smtp_server_input_callback_t(void *context);

void smtp_server_connection_debug(struct smtp_server_connection *conn,
	const char *format, ...) ATTR_FORMAT(2, 3);

struct connection_list *smtp_server_connection_list_init(void);

void smtp_server_connection_switch_ioloop(struct smtp_server_connection *conn);

void smtp_server_connection_handle_output_error(
	struct smtp_server_connection *conn);
void smtp_server_connection_trigger_output(struct smtp_server_connection *conn);
bool smtp_server_connection_pending_payload(struct smtp_server_connection *conn);

void smtp_server_connection_cork(struct smtp_server_connection *conn);
void smtp_server_connection_uncork(struct smtp_server_connection *conn);

void smtp_server_connection_input_halt(struct smtp_server_connection *conn);
void smtp_server_connection_input_resume(struct smtp_server_connection *conn);
void smtp_server_connection_input_capture(
	struct smtp_server_connection *conn,
	smtp_server_input_callback_t *callback, void *context);
#define smtp_server_connection_input_capture(conn, callback, context) \
	smtp_server_connection_input_capture(conn + \
		CALLBACK_TYPECHECK(callback, void (*)(typeof(context))), \
		(smtp_server_input_callback_t *)callback, context)

void smtp_server_connection_timeout_stop(struct smtp_server_connection *conn);
void smtp_server_connection_timeout_start(struct smtp_server_connection *conn);
void smtp_server_connection_timeout_reset(struct smtp_server_connection *conn);

void smtp_server_connection_send_line(struct smtp_server_connection *conn,
	const char *fmt, ...) ATTR_FORMAT(2, 3);
void smtp_server_connection_reply_lines(struct smtp_server_connection *conn,
				        unsigned int status,
					const char *enh_code,
					const char *const *text_lines);
void smtp_server_connection_reply_immediate(
	struct smtp_server_connection *conn, unsigned int status,
	const char *fmt, ...) ATTR_FORMAT(3, 4);

void smtp_server_connection_reset_state(struct smtp_server_connection *conn);
void smtp_server_connection_set_state(struct smtp_server_connection *conn,
	enum smtp_server_state state);

int smtp_server_connection_ssl_init(struct smtp_server_connection *conn);

void smtp_server_connection_clear(struct smtp_server_connection *conn);

struct smtp_server_transaction *
smtp_server_connection_get_transaction(struct smtp_server_connection *conn);

void smtp_server_connection_set_proxy_data(struct smtp_server_connection *conn,
	const struct smtp_proxy_data *proxy_data);

/*
 * Recipient
 */

struct smtp_server_recipient *
smtp_server_recipient_create(struct smtp_server_cmd_ctx *cmd,
			     const struct smtp_address *rcpt_to,
			     const struct smtp_params_rcpt *params);
void smtp_server_recipient_ref(struct smtp_server_recipient *rcpt);
bool smtp_server_recipient_unref(struct smtp_server_recipient **_rcpt);
void smtp_server_recipient_destroy(struct smtp_server_recipient **_rcpt);

bool smtp_server_recipient_approved(struct smtp_server_recipient **_rcpt);
void smtp_server_recipient_denied(struct smtp_server_recipient *rcpt,
				  const struct smtp_server_reply *reply);

void smtp_server_recipient_last_data(struct smtp_server_recipient *rcpt,
				     struct smtp_server_cmd_ctx *cmd);

void smtp_server_recipient_reset(struct smtp_server_recipient *rcpt);
void smtp_server_recipient_finished(struct smtp_server_recipient *rcpt,
				    const struct smtp_server_reply *reply);

bool smtp_server_recipient_call_hooks(
	struct smtp_server_recipient **_rcpt,
	enum smtp_server_recipient_hook_type type);

/*
 * Transaction
 */

struct smtp_server_transaction *
smtp_server_transaction_create(struct smtp_server_connection *conn,
			       enum smtp_server_transaction_flags flags,
			       const struct smtp_address *mail_from,
			       const struct smtp_params_mail *params,
			       const struct timeval *timestamp);
void smtp_server_transaction_free(struct smtp_server_transaction **_trans);

void smtp_server_transaction_add_rcpt(struct smtp_server_transaction *trans,
				      struct smtp_server_recipient *rcpt);
bool smtp_server_transaction_has_rcpt(struct smtp_server_transaction *trans);
unsigned int
smtp_server_transaction_rcpt_count(struct smtp_server_transaction *trans);

void smtp_server_transaction_last_data(struct smtp_server_transaction *trans,
				       struct smtp_server_cmd_ctx *cmd);

void smtp_server_transaction_received(struct smtp_server_transaction *trans,
				      uoff_t data_size);

void smtp_server_transaction_reset(struct smtp_server_transaction *trans);
void smtp_server_transaction_finished(struct smtp_server_transaction *trans,
				      struct smtp_server_cmd_ctx *cmd);

/*
 * Server
 */

int smtp_server_init_ssl_ctx(struct smtp_server *server, const char **error_r);

#endif
