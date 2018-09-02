#ifndef SMTP_SERVER_H
#define SMTP_SERVER_H

#include "smtp-common.h"
#include "smtp-command.h"
#include "smtp-params.h"

struct smtp_address;
struct smtp_reply;
struct smtp_command;

struct smtp_server_helo_data;

struct smtp_server_esmtp_param;
struct smtp_server_cmd_ehlo;
struct smtp_server_cmd_mail;
struct smtp_server_cmd_ctx;
struct smtp_server_command;
struct smtp_server_reply;

struct smtp_server;

/*
 * Types
 */

enum smtp_server_state {
	SMTP_SERVER_STATE_GREETING = 0,
	SMTP_SERVER_STATE_XCLIENT,
	SMTP_SERVER_STATE_HELO,
	SMTP_SERVER_STATE_STARTTLS,
	SMTP_SERVER_STATE_AUTH,
	SMTP_SERVER_STATE_READY,
	SMTP_SERVER_STATE_MAIL_FROM,
	SMTP_SERVER_STATE_RCPT_TO,
	SMTP_SERVER_STATE_DATA,
};
extern const char *const smtp_server_state_names[];

struct smtp_server_helo_data {
	const char *domain;

	bool domain_valid:1;  /* valid domain/literal specified */
	bool old_smtp:1;      /* client sent HELO rather than EHLO */
};

/*
 * Transaction
 */

struct smtp_server_recipient {
	struct smtp_address *path;
	struct smtp_params_rcpt params;

	void *context;
};
ARRAY_DEFINE_TYPE(smtp_server_recipient, struct smtp_server_recipient *);

struct smtp_server_transaction {
	pool_t pool;
	struct smtp_server_connection *conn;
	const char *id;
	struct timeval timestamp;

	struct smtp_address *mail_from;
	struct smtp_params_mail params;
	ARRAY_TYPE(smtp_server_recipient) rcpt_to;

	void *context;
};

struct smtp_server_recipient *
smtp_server_transaction_find_rcpt_duplicate(
	struct smtp_server_transaction *trans,
	struct smtp_server_recipient *rcpt);

void smtp_server_transaction_fail_data(
	struct smtp_server_transaction *trans,
	struct smtp_server_cmd_ctx *data_cmd,
	unsigned int status, const char *enh_code,
	const char *fmt, va_list args) ATTR_FORMAT(5, 0);

void smtp_server_transaction_write_trace_record(string_t *str,
	struct smtp_server_transaction *trans);

/*
 * Callbacks
 */

struct smtp_server_cmd_helo {
	struct smtp_server_helo_data helo;

	bool first:1;         /* this is the first */
	bool changed:1;       /* this EHLO/HELO/LHLO is the first or
	                         different from a previous one */
};

struct smtp_server_cmd_mail {
	struct smtp_address *path;
	struct smtp_params_mail params;

	struct timeval timestamp;
};

struct smtp_server_cmd_rcpt {
	struct smtp_address *path;
	struct smtp_params_rcpt params;

	/* called once the recipient is definitively added to the transaction */
	void (*hook_finished)(struct smtp_server_cmd_ctx *cmd,
			      struct smtp_server_transaction *trans,
			      struct smtp_server_recipient *rcpt,
			      unsigned int index);

	void *trans_context;
};

struct smtp_server_cmd_auth {
	const char *sasl_mech;
	const char *initial_response;
};

struct smtp_server_callbacks {
	/* Command callbacks:

	   These are used to override/implement the behavior of the various core
	   SMTP commands. Commands are handled asynchronously, which means that
	   the command is not necessarily finished when the callback ends. A
	   command is finished either when 1 is returned or a reply is submitted
	   for it. When a callback returns 0, the command implementation is
	   waiting for an external event and when it returns -1 an error
	   occurred. When 1 is returned, a default success reply is set if no
	   reply was submitted. Not submitting an error reply when -1 is
	   returned causes an assert fail. Except for RCPT and DATA, all these
	   callbacks are optional to implement; appropriate default behavior is
	   provided.

	   The SMTP server API takes care of transaction state checking.
	   However, until all previous commands are handled, a transaction
	   command cannot rely on the transaction state being final. Use
	   cmd->hook_next to get notified when all previous commands are
	   finished and the current command is next in line to reply.

	   If the implementation does not need asynchronous behavior, set
	   max_pipelined_commands=1 and don't return 0 from any command handler.
	  */

	/* HELO/EHLO/LHLO */
	int (*conn_cmd_helo)(void *conn_ctx,
		struct smtp_server_cmd_ctx *cmd,
		struct smtp_server_cmd_helo *data);
	/* STARTTLS */
	int (*conn_cmd_starttls)(void *conn_ctx,
		struct smtp_server_cmd_ctx *cmd);
	/* AUTH */
	int (*conn_cmd_auth)(void *conn_ctx,
		struct smtp_server_cmd_ctx *cmd,
		struct smtp_server_cmd_auth *data);
	int (*conn_cmd_auth_continue)(void *conn_ctx,
		struct smtp_server_cmd_ctx *cmd, const char *response);
	/* MAIL */
	int (*conn_cmd_mail)(void *conn_ctx,
		struct smtp_server_cmd_ctx *cmd,
		struct smtp_server_cmd_mail *data);
	/* RCPT */
	int (*conn_cmd_rcpt)(void *conn_ctx,
		struct smtp_server_cmd_ctx *cmd,
		struct smtp_server_cmd_rcpt *data);
	/* RSET */
	int (*conn_cmd_rset)(void *conn_ctx,
		struct smtp_server_cmd_ctx *cmd);
	/* DATA */
	int (*conn_cmd_data_begin)(void *conn_ctx,
		struct smtp_server_cmd_ctx *cmd,
		struct smtp_server_transaction *trans,
		struct istream *data_input);
	int (*conn_cmd_data_continue)(void *conn_ctx,
		struct smtp_server_cmd_ctx *cmd,
		struct smtp_server_transaction *trans);
	/* VRFY */
	int (*conn_cmd_vrfy)(void *conn_ctx,
		struct smtp_server_cmd_ctx *cmd,
		const char *param);
	/* NOOP */
	int (*conn_cmd_noop)(void *conn_ctx,
		struct smtp_server_cmd_ctx *cmd);
	/* QUIT */
	int (*conn_cmd_quit)(void *conn_ctx,
		struct smtp_server_cmd_ctx *cmd);
	/* XCLIENT */
	void (*conn_cmd_xclient)(void *conn_ctx,
		struct smtp_server_cmd_ctx *cmd,
		struct smtp_proxy_data *data);

	/* Command input callbacks:

	   These can be used to do stuff before and after a pipelined group of
	   commands is read.
	 */
	void (*conn_cmd_input_pre)(void *context);
	void (*conn_cmd_input_post)(void *context);

	/* Transaction events */
	void (*conn_trans_start)(void *context,
				 struct smtp_server_transaction *trans);
	void (*conn_trans_free)(void *context,
				struct smtp_server_transaction *trans);

	/* Protocol state events */
	void (*conn_state_changed)(void *context,
				   enum smtp_server_state newstate);

	/* Proxy data */
	void (*conn_proxy_data_updated)(void *conn_ctx,
					const struct smtp_proxy_data *data);

	/* Connection */
	int (*conn_start_tls)(void *conn_ctx,
		struct istream **input, struct ostream **output);
	void (*conn_disconnect)(void *context, const char *reason);
	void (*conn_destroy)(void *context);

	/* Security */
	bool (*conn_is_trusted)(void *context);
};

/*
 * Server
 */

enum smtp_server_workarounds {
	SMTP_SERVER_WORKAROUND_WHITESPACE_BEFORE_PATH   = BIT(0),
	SMTP_SERVER_WORKAROUND_MAILBOX_FOR_PATH         = BIT(1)
};

struct smtp_server_settings {
	enum smtp_protocol protocol;
	enum smtp_capability capabilities;
	enum smtp_server_workarounds workarounds;

	const char *hostname;
	const char *login_greeting;
	const char *rawlog_dir;

	/* SSL settings; if NULL, master_service_ssl_init() is used instead */
	const struct ssl_iostream_settings *ssl;

	/* The maximum time in milliseconds a client is allowed to be idle
	   before it is disconnected. */
	unsigned int max_client_idle_time_msecs;

	/* maximum number of commands in pipeline per connection (default = 1)
	 */
	unsigned int max_pipelined_commands;

	/* maximum number of sequential bad commands */
	unsigned int max_bad_commands;

	/* maximum number of recipients in a transaction
	   (0 means unlimited, which is the default) */
	unsigned int max_recipients;

	/* command limits */
	struct smtp_command_limits command_limits;

	/* message size limit */
	uoff_t max_message_size;

	/* accept these additional custom XCLIENT fields */
	const char *const *xclient_extensions;

	/* The kernel send/receive buffer sizes used for the connection sockets.
	   Configuring this is mainly useful for the test suite. The kernel
	   defaults are used when these settings are 0. */
	size_t socket_send_buffer_size;
	size_t socket_recv_buffer_size;

	bool debug:1;
	bool auth_optional:1;
	bool tls_required:1;
	bool rcpt_domain_optional:1;
	bool param_extensions:1;
};

struct smtp_server_stats {
	unsigned int command_count, reply_count;
	uoff_t input, output;
};

struct smtp_server *smtp_server_init(const struct smtp_server_settings *set);
void smtp_server_deinit(struct smtp_server **_server);

/*
 * Connection
 */

/* Create connection. It is still inactive and needs to be started with
   one of the functions below. */
struct smtp_server_connection *
smtp_server_connection_create(struct smtp_server *server,
	int fd_in, int fd_out,
	const struct ip_addr *remote_ip, in_port_t remote_port,
	bool ssl_start, const struct smtp_server_settings *set,
	const struct smtp_server_callbacks *callbacks, void *context)
	ATTR_NULL(4, 6, 8);
struct smtp_server_connection *
smtp_server_connection_create_from_streams(struct smtp_server *server,
	struct istream *input, struct ostream *output,
	const struct ip_addr *remote_ip, in_port_t remote_port,
	const struct smtp_server_settings *set,
	const struct smtp_server_callbacks *callbacks, void *context)
	ATTR_NULL(4, 6, 8);

void smtp_server_connection_ref(struct smtp_server_connection *conn);
bool smtp_server_connection_unref(struct smtp_server_connection **_conn);

/* Initialize the connection with state and data from login service */
void smtp_server_connection_login(struct smtp_server_connection *conn,
				  const char *username, const char *helo,
				  const unsigned char *pdata,
				  unsigned int pdata_len, bool ssl_secured);

/* Start the connection. Establishes SSL layer immediately if instructed,
   and sends the greeting once the connection is ready for commands. */
void smtp_server_connection_start(struct smtp_server_connection *conn);
/* Start the connection, but only establish SSL layer and send greeting;
   handling command input is held off until smtp_server_connection_resume() is
   called. */
void smtp_server_connection_start_pending(struct smtp_server_connection *conn);

/* Halt connection command input and idle timeout entirely. */
void smtp_server_connection_halt(struct smtp_server_connection *conn);
/* Resume connection command input and idle timeout. */
void smtp_server_connection_resume(struct smtp_server_connection *conn);

void smtp_server_connection_input_lock(struct smtp_server_connection *conn);
void smtp_server_connection_input_unlock(struct smtp_server_connection *conn);

void smtp_server_connection_set_streams(struct smtp_server_connection *conn,
	struct istream *input, struct ostream *output);
void smtp_server_connection_set_ssl_streams(struct smtp_server_connection *conn,
	struct istream *input, struct ostream *output);

void smtp_server_connection_close(struct smtp_server_connection **_conn,
				  const char *reason) ATTR_NULL(2);
void smtp_server_connection_terminate(struct smtp_server_connection **_conn,
				      const char *enh_code, const char *reason)
	ATTR_NULL(3);

bool smtp_server_connection_data_check_state(struct smtp_server_cmd_ctx *cmd);
void smtp_server_connection_data_chunk_init(struct smtp_server_cmd_ctx *cmd);
int smtp_server_connection_data_chunk_add(struct smtp_server_cmd_ctx *cmd,
	struct istream *chunk, uoff_t chunk_size, bool chunk_last,
	bool client_input);

enum smtp_server_state
smtp_server_connection_get_state(struct smtp_server_connection *conn);
const char *
smtp_server_connection_get_security_string(struct smtp_server_connection *conn);
struct smtp_server_transaction *
smtp_server_connection_get_transaction(struct smtp_server_connection *conn);
const char *
smtp_server_connection_get_transaction_id(struct smtp_server_connection *conn);
const struct smtp_server_stats *
smtp_server_connection_get_stats(struct smtp_server_connection *conn);
void *smtp_server_connection_get_context(struct smtp_server_connection *conn)
	ATTR_PURE;
enum smtp_protocol
smtp_server_connection_get_protocol(struct smtp_server_connection *conn)
	ATTR_PURE;
const char *
smtp_server_connection_get_protocol_name(struct smtp_server_connection *conn);
struct smtp_server_helo_data *
smtp_server_connection_get_helo_data(struct smtp_server_connection *conn);
void smtp_server_connection_get_proxy_data(struct smtp_server_connection *conn,
	struct smtp_proxy_data *proxy_data);

void smtp_server_connection_set_capabilities(
	struct smtp_server_connection *conn, enum smtp_capability capabilities);

bool smtp_server_connection_is_ssl_secured(struct smtp_server_connection *conn);
bool smtp_server_connection_is_trusted(struct smtp_server_connection *conn);

/*
 * Command
 */

enum smtp_server_command_flags {
	SMTP_SERVER_CMD_FLAG_PRETLS  = BIT(0),
	SMTP_SERVER_CMD_FLAG_PREAUTH = BIT(1)
};

enum smtp_server_command_hook_type {
	/* next: command is next to reply but has not submittted all replies
	   yet. */
	SMTP_SERVER_COMMAND_HOOK_NEXT,
	/* replied: command has submitted all replies. */
	SMTP_SERVER_COMMAND_HOOK_REPLIED,
	/* completed: server is about to send last replies for this command. */
	SMTP_SERVER_COMMAND_HOOK_COMPLETED,
	/* destroy: command is about to be destroyed. */
	SMTP_SERVER_COMMAND_HOOK_DESTROY
};

/* Commands are handled asynchronously, which means that the command is not
   necessary finished when the start function ends. A command is finished
   when a reply is submitted for it. Several command hooks are available to
   get notified about events in the command's life cycle.
 */

typedef void smtp_server_cmd_input_callback_t(struct smtp_server_cmd_ctx *cmd);
typedef void smtp_server_cmd_start_func_t(struct smtp_server_cmd_ctx *cmd,
					  const char *params);
typedef void smtp_server_cmd_func_t(struct smtp_server_cmd_ctx *cmd,
				    void *context);

struct smtp_server_cmd_ctx {
	pool_t pool;
	const char *name;

	struct smtp_server *server;
	struct smtp_server_connection *conn;
	struct smtp_server_command *cmd;
};

/* Hooks:

 */

void smtp_server_command_add_hook(struct smtp_server_command *cmd,
				  enum smtp_server_command_hook_type type,
				  smtp_server_cmd_func_t func,
				  void *context);
#define smtp_server_command_add_hook(_cmd, _type, _func, _context) \
	smtp_server_command_add_hook((_cmd), (_type) + \
		CALLBACK_TYPECHECK(_func, void (*)( \
			struct smtp_server_cmd_ctx *, typeof(_context))), \
		(smtp_server_cmd_func_t *)(_func), (_context))
void smtp_server_command_remove_hook(struct smtp_server_command *cmd,
				     enum smtp_server_command_hook_type type,
				     smtp_server_cmd_func_t *func);
#define smtp_server_command_remove_hook(_cmd, _type, _func) \
	smtp_server_command_remove_hook((_cmd), (_type), \
		(smtp_server_cmd_func_t *)(_func));

/* The core SMTP commands are pre-registered. Special connection callbacks are
   provided for the core SMTP commands. Only use this command registration API
   when custom/extension SMTP commands are required.
 */
void smtp_server_command_register(struct smtp_server *server, const char *name,
				  smtp_server_cmd_start_func_t *func,
				  enum smtp_server_command_flags);
void smtp_server_command_unregister(struct smtp_server *server,
				    const char *name);

void smtp_server_command_set_reply_count(struct smtp_server_command *cmd,
					 unsigned int count);

void smtp_server_command_fail(struct smtp_server_command *cmd,
			      unsigned int status, const char *enh_code,
			      const char *fmt, ...) ATTR_FORMAT(4, 5);

struct smtp_server_reply *
smtp_server_command_get_reply(struct smtp_server_command *cmd,
			      unsigned int idx);
bool smtp_server_command_reply_status_equals(struct smtp_server_command *cmd,
					     unsigned int status);
bool smtp_server_command_is_replied(struct smtp_server_command *cmd);
bool smtp_server_command_replied_success(struct smtp_server_command *cmd);

void smtp_server_command_input_lock(struct smtp_server_cmd_ctx *cmd);
void smtp_server_command_input_unlock(struct smtp_server_cmd_ctx *cmd);
void smtp_server_command_input_capture(struct smtp_server_cmd_ctx *cmd,
	smtp_server_cmd_input_callback_t *callback);

/* AUTH */

void smtp_server_cmd_auth_send_challenge(struct smtp_server_cmd_ctx *cmd,
					 const char *challenge);
void smtp_server_cmd_auth_success(struct smtp_server_cmd_ctx *cmd,
	const char *username, const char *success_msg)
	ATTR_NULL(3);

/* DATA */

bool smtp_server_cmd_data_check_size(struct smtp_server_cmd_ctx *cmd);

/*
 * Reply
 */

struct smtp_server_reply *
smtp_server_reply_create_index(struct smtp_server_command *cmd,
	unsigned int index, unsigned int status, const char *enh_code)
	ATTR_NULL(3);
struct smtp_server_reply *
smtp_server_reply_create(struct smtp_server_command *cmd,
	unsigned int status, const char *enh_code) ATTR_NULL(3);
struct smtp_server_reply *
smtp_server_reply_create_forward(struct smtp_server_command *cmd,
	unsigned int index, const struct smtp_reply *from);

void smtp_server_reply_add_text(struct smtp_server_reply *reply,
	const char *line);
void smtp_server_reply_submit(struct smtp_server_reply *reply);
void smtp_server_reply_submit_duplicate(struct smtp_server_cmd_ctx *_cmd,
					unsigned int index,
					unsigned int from_index);

/* Submit a reply for the command at the specified index (> 0 only if more than
   a single reply is expected). */
void smtp_server_reply_indexv(struct smtp_server_cmd_ctx *_cmd,
	unsigned int index, unsigned int status, const char *enh_code,
	const char *fmt, va_list args) ATTR_FORMAT(5, 0);
void smtp_server_reply_index(struct smtp_server_cmd_ctx *_cmd,
	unsigned int index, unsigned int status, const char *enh_code,
	const char *fmt, ...) ATTR_FORMAT(5, 6);
/* Submit the reply for the specified command. */
void smtp_server_reply(struct smtp_server_cmd_ctx *_cmd,
	unsigned int status, const char *enh_code, const char *fmt, ...)
	ATTR_FORMAT(4, 5);
/* Forward a reply for the command at the specified index (> 0 only if more
   than a single reply is expected). */
void smtp_server_reply_index_forward(struct smtp_server_cmd_ctx *cmd,
	unsigned int index, const struct smtp_reply *from);
/* Forward the reply for the specified command. */
void smtp_server_reply_forward(struct smtp_server_cmd_ctx *cmd,
			       const struct smtp_reply *from);
/* Submit the same message for all expected replies for this command. */
void smtp_server_reply_all(struct smtp_server_cmd_ctx *_cmd,
			   unsigned int status, const char *enh_code,
			   const char *fmt, ...) ATTR_FORMAT(4, 5);
/* Submit and send the same message for all expected replies for this command
   early; i.e., no matter whether all command data is received completely. */
void smtp_server_reply_early(struct smtp_server_cmd_ctx *_cmd,
			     unsigned int status, const char *enh_code,
			     const char *fmt, ...) ATTR_FORMAT(4, 5);

/* Reply the command with a 221 bye message */
void smtp_server_reply_quit(struct smtp_server_cmd_ctx *_cmd);

void smtp_server_switch_ioloop(struct smtp_server *server);

/* EHLO */

struct smtp_server_reply *
smtp_server_reply_create_ehlo(struct smtp_server_command *cmd);
void smtp_server_reply_ehlo_add(struct smtp_server_reply *reply,
				const char *keyword);
void smtp_server_reply_ehlo_add_param(struct smtp_server_reply *reply,
	const char *keyword, const char *param_fmt, ...) ATTR_FORMAT(3, 4);
void smtp_server_reply_ehlo_add_xclient(struct smtp_server_reply *reply);

#endif
