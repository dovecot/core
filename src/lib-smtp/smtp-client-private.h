#ifndef SMTP_CLIENT_PRIVATE_H
#define SMTP_CLIENT_PRIVATE_H

#include "connection.h"

#include "smtp-common.h"
#include "smtp-params.h"
#include "smtp-client.h"
#include "smtp-client-command.h"
#include "smtp-client-transaction.h"
#include "smtp-client-connection.h"

#define SMTP_CLIENT_BASE_LINE_LENGTH_LIMIT 512
#define SMTP_CLIENT_DATA_CHUNK_SIZE IO_BLOCK_SIZE

struct smtp_client_command {
	pool_t pool;
	int refcount;
	struct event *event;

	struct smtp_client_command *prev, *next;

	buffer_t *data;
	unsigned int send_pos;
	const char *name;

	enum smtp_client_command_flags flags;

	struct smtp_client_connection *conn;
	enum smtp_client_command_state state;
	unsigned int replies_expected;
	unsigned int replies_seen;

	struct istream *stream;
	uoff_t stream_size;

	struct smtp_reply *delayed_failure;

	smtp_client_command_callback_t *callback;
	void *context;

	void (*abort_callback)(void *context);
	void *abort_context;

	void (*sent_callback)(void *context);
	void *sent_context;

	bool has_stream:1;
	bool stream_dot:1;
	bool stream_finished:1;
	bool ehlo:1;
	bool locked:1;
	bool plug:1;
	bool aborting:1;
	bool delay_failure:1;
	bool delaying_failure:1;
};

struct smtp_client_transaction_mail {
	pool_t pool;
	struct smtp_client_transaction *trans;

	struct smtp_client_transaction_mail *prev, *next;

	struct smtp_address *mail_from;
	struct smtp_params_mail mail_params;

	smtp_client_command_callback_t *mail_callback;
	void *context;

	struct smtp_client_command *cmd_mail_from;
};

struct smtp_client_transaction_rcpt {
	pool_t pool;
	struct smtp_client_transaction *trans;

	struct smtp_client_transaction_rcpt *prev, *next;

	struct smtp_address *rcpt_to;
	struct smtp_params_rcpt rcpt_params;

	smtp_client_command_callback_t *rcpt_callback;
	void *context;

	smtp_client_command_callback_t *data_callback;
	void *data_context;

	struct smtp_client_command *cmd_rcpt_to;

	bool external_pool:1;
	bool queued:1;
	bool failed:1;
};

struct smtp_client_transaction {
	pool_t pool;
	int refcount;
	struct event *event;

	struct smtp_client_transaction *prev, *next;

	struct smtp_client_connection *conn;
	enum smtp_client_transaction_flags flags;

	enum smtp_client_transaction_state state;
	struct smtp_client_command *cmd_data, *cmd_rset;
	struct smtp_client_command *cmd_plug, *cmd_last;
	struct smtp_reply *failure, *mail_failure;

	struct smtp_client_transaction_mail *mail_head, *mail_tail;
	struct smtp_client_transaction_mail *mail_send;

	struct smtp_client_transaction_rcpt *rcpts_queue_head, *rcpts_queue_tail;
	struct smtp_client_transaction_rcpt *rcpts_send;
	struct smtp_client_transaction_rcpt *rcpts_head, *rcpts_tail;
	struct smtp_client_transaction_rcpt *rcpts_data;
	unsigned int rcpts_queue_count;
	unsigned int rcpts_count;

	struct istream *data_input;
	smtp_client_command_callback_t *data_callback;
	void *data_context;

	smtp_client_command_callback_t *reset_callback;
	void *reset_context;

	smtp_client_transaction_callback_t *callback;
	void *context;

	struct smtp_client_transaction_times times;

	unsigned int finish_timeout_msecs;
	struct timeout *to_finish, *to_send;

	bool immediate:1;
	bool sender_accepted:1;
	bool data_provided:1;
	bool reset:1;
	bool finished:1;
	bool submitting:1;
	bool failing:1;
	bool submitted_data:1;
};

struct smtp_client_connection {
	struct connection conn;
	pool_t pool;
	int refcount;
	struct event *event;

	struct smtp_client *client;
	unsigned int id;

	enum smtp_protocol protocol;
	const char *path, *host;
	in_port_t port;
	enum smtp_client_connection_ssl_mode ssl_mode;

	struct smtp_client_settings set;
	char *password;
	ARRAY_TYPE(const_string) extra_capabilities;

	pool_t cap_pool;
	struct {
		enum smtp_capability standard;
		ARRAY(struct smtp_capability_extra) extra;
		const char **auth_mechanisms;
		const char **xclient_args;
		uoff_t size;
	} caps;

	struct smtp_reply_parser *reply_parser;
	struct smtp_reply reply;
	unsigned int xclient_replies_expected;

	struct dns_lookup *dns_lookup;
	struct dsasl_client *sasl_client;
	struct timeout *to_connect, *to_trans, *to_commands, *to_cmd_fail;
	struct io *io_cmd_payload;

	struct istream *raw_input;
	struct ostream *raw_output, *dot_output;

	struct ssl_iostream_context *ssl_ctx;
	struct ssl_iostream *ssl_iostream;

	enum smtp_client_connection_state state;

	smtp_client_command_callback_t *login_callback;
	void *login_context;

	/* commands pending in queue to be sent */
	struct smtp_client_command *cmd_send_queue_head, *cmd_send_queue_tail;
	unsigned int cmd_send_queue_count;
	/* commands that have been (mostly) sent, waiting for response */
	struct smtp_client_command *cmd_wait_list_head, *cmd_wait_list_tail;
	unsigned int cmd_wait_list_count;
	/* commands that have failed before submission */
	struct smtp_client_command *cmd_fail_list;
	/* command sending data stream */
	struct smtp_client_command *cmd_streaming;

	/* active transactions */
	struct smtp_client_transaction *transactions_head, *transactions_tail;

	unsigned int ips_count, prev_connect_idx;
	struct ip_addr *ips;

	bool old_smtp:1;
	bool authenticated:1;
	bool xclient_sent:1;
	bool connect_failed:1;
	bool connect_succeeded:1;
	bool handshake_failed:1;
	bool corked:1;
	bool sent_quit:1;
	bool sending_command:1;
	bool reset_needed:1;
	bool failing:1;
	bool destroying:1;
	bool closed:1;
};

struct smtp_client {
	pool_t pool;

	struct smtp_client_settings set;

	struct event *event;
	struct ioloop *ioloop;
	struct ssl_iostream_context *ssl_ctx;

	struct connection_list *conn_list;
};

/*
 * Command
 */

void smtp_client_command_free(struct smtp_client_command *cmd);
int smtp_client_command_send_more(struct smtp_client_connection *conn);
int smtp_client_command_input_reply(struct smtp_client_command *cmd,
				    const struct smtp_reply *reply);

void smtp_client_command_drop_callback(struct smtp_client_command *cmd);

void smtp_client_command_fail(struct smtp_client_command **_cmd,
			      unsigned int status, const char *error);
void smtp_client_command_fail_reply(struct smtp_client_command **_cmd,
				    const struct smtp_reply *reply);

void smtp_client_commands_list_abort(struct smtp_client_command *cmds_list,
				     unsigned int cmds_list_count);
void smtp_client_commands_list_fail_reply(
	struct smtp_client_command *cmds_list, unsigned int cmds_list_count,
	const struct smtp_reply *reply);

void smtp_client_commands_abort_delayed(struct smtp_client_connection *conn);
void smtp_client_commands_fail_delayed(struct smtp_client_connection *conn);

/*
 * Transaction
 */

void smtp_client_transaction_connection_result(
	struct smtp_client_transaction *trans,
	const struct smtp_reply *reply);
void smtp_client_transaction_switch_ioloop(
	struct smtp_client_transaction *trans);

/*
 * Connection
 */

struct connection_list *smtp_client_connection_list_init(void);

void smtp_client_connection_send_xclient(struct smtp_client_connection *conn);

void smtp_client_connection_fail(struct smtp_client_connection *conn,
				 unsigned int status, const char *error);

void smtp_client_connection_handle_output_error(
	struct smtp_client_connection *conn);
void smtp_client_connection_trigger_output(
	struct smtp_client_connection *conn);

void smtp_client_connection_start_cmd_timeout(
	struct smtp_client_connection *conn);
void smtp_client_connection_update_cmd_timeout(
	struct smtp_client_connection *conn);

void smtp_client_connection_add_transaction(
	struct smtp_client_connection *conn,
	struct smtp_client_transaction *trans);
void smtp_client_connection_abort_transaction(
	struct smtp_client_connection *conn,
	struct smtp_client_transaction *trans);
void smtp_client_connection_next_transaction(
	struct smtp_client_connection *conn,
	struct smtp_client_transaction *trans);

/*
 * Client
 */

int smtp_client_init_ssl_ctx(struct smtp_client *client, const char **error_r);

#endif
