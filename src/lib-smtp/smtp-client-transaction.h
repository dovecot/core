#ifndef SMTP_CLIENT_TRANSACTION_H
#define SMTP_CLIENT_TRANSACTION_H

#include "net.h"
#include "istream.h"

struct smtp_address;
struct smtp_client_transaction;

enum smtp_client_transaction_state {
	SMTP_CLIENT_TRANSACTION_STATE_NEW = 0,
	SMTP_CLIENT_TRANSACTION_STATE_PENDING,
	SMTP_CLIENT_TRANSACTION_STATE_MAIL_FROM,
	SMTP_CLIENT_TRANSACTION_STATE_RCPT_TO,
	SMTP_CLIENT_TRANSACTION_STATE_DATA,
	SMTP_CLIENT_TRANSACTION_STATE_RESET,
	SMTP_CLIENT_TRANSACTION_STATE_FINISHED,
	SMTP_CLIENT_TRANSACTION_STATE_ABORTED
};
extern const char *const smtp_client_transaction_state_names[];

struct smtp_client_transaction_times {
	struct timeval started;
	struct timeval finished;
};

/* Called when the transaction is finished, either because the MAIL FROM
   failed, all RCPT TOs failed or because all DATA replies have been
   received. */
typedef void
smtp_client_transaction_callback_t(void *context);

struct smtp_client_transaction *
smtp_client_transaction_create(struct smtp_client_connection *conn,
		const struct smtp_address *mail_from,
		const struct smtp_params_mail *mail_params, unsigned int flags,
		smtp_client_transaction_callback_t *callback, void *context)
		ATTR_NULL(2, 3, 5);
#define smtp_client_transaction_create(conn, \
		mail_from, mail_params, callback, context) \
	smtp_client_transaction_create(conn, mail_from, mail_params, \
		0 + CALLBACK_TYPECHECK(callback, void (*)(typeof(context))), \
		(smtp_client_transaction_callback_t *)callback, context)

void smtp_client_transaction_ref(struct smtp_client_transaction *trans);
void smtp_client_transaction_unref(struct smtp_client_transaction **_trans);
void smtp_client_transaction_destroy(struct smtp_client_transaction **trans);

void smtp_client_transaction_abort(struct smtp_client_transaction *trans);
void smtp_client_transaction_fail_reply(struct smtp_client_transaction *trans,
	const struct smtp_reply *reply);
void smtp_client_transaction_fail(struct smtp_client_transaction *trans,
	unsigned int status, const char *error);

void smtp_client_transaction_set_timeout(struct smtp_client_transaction *trans,
	unsigned int timeout_msecs);

/* Start the transaction with a MAIL command. The mail_from_callback is
   called once the server replies to the MAIL FROM command. Calling this
   function is not mandatory; it is called implicitly by
   smtp_client_transaction_send() if the transaction wasn't already started.
 */
void smtp_client_transaction_start(struct smtp_client_transaction *trans,
	smtp_client_command_callback_t *mail_from_callback, void *context);
#define smtp_client_transaction_start(trans, mail_from_callback, context) \
	smtp_client_transaction_start(trans, \
		(smtp_client_command_callback_t *)mail_from_callback, \
		context + CALLBACK_TYPECHECK(mail_from_callback, void (*)( \
			const struct smtp_reply *reply, typeof(context))))

/* Add recipient to the transaction with a RCPT TO command. The
   rcpt_to_callback is called once the server replies to the RCPT TO command.
   If RCPT TO succeeded, the data_callback is called once the server replies
   to the DATA command. The data_callback will not be called until
   smtp_client_transaction_send() is called for the transaction (see
   below). Until that time, any failure is remembered.
 */
void smtp_client_transaction_add_rcpt(
	struct smtp_client_transaction *trans,
	const struct smtp_address *rcpt_to,
	const struct smtp_params_rcpt *rcpt_params,
	smtp_client_command_callback_t *rcpt_callback,
	smtp_client_command_callback_t *data_callback, void *context)
	ATTR_NULL(3,5,6);
#define smtp_client_transaction_add_rcpt(trans, \
		rcpt_to, rcpt_params, rcpt_callback, data_callback, context) \
	smtp_client_transaction_add_rcpt(trans, rcpt_to + \
		CALLBACK_TYPECHECK(rcpt_callback, void (*)( \
			const struct smtp_reply *reply, typeof(context))) + \
		CALLBACK_TYPECHECK(data_callback, void (*)( \
			const struct smtp_reply *reply, typeof(context))), \
		rcpt_params, \
		(smtp_client_command_callback_t *)rcpt_callback, \
		(smtp_client_command_callback_t *)data_callback, context)

/* Start sending input stream as DATA. This completes the transaction, which
   means that any pending failures that got recorded before this function was
   called will be triggered now. If any RCPT TO succeeded, the provided
   data_callback is called once the server replies to the DATA command. This
   callback is mainly useful for SMTP, for LMTP it will only yield the reply for
   the last recipient. This function starts the transaction implicitly. */
void smtp_client_transaction_send(
	struct smtp_client_transaction *trans, struct istream *data_input,
	smtp_client_command_callback_t *data_callback, void *data_context);
#define smtp_client_transaction_send(trans, \
		data_input, data_callback, data_context) \
	smtp_client_transaction_send(trans, data_input + \
		CALLBACK_TYPECHECK(data_callback, void (*)( \
			const struct smtp_reply *reply, typeof(data_context))), \
		(smtp_client_command_callback_t *)data_callback, data_context)

/* Gracefully reset the transaction by sending the RSET command and waiting for
   the response. This does not try to abort pending MAIL and RCPT commands,
   allowing the transaction to be evaluated without proceeding with the DATA
   command. */
void smtp_client_transaction_reset(
	struct smtp_client_transaction *trans,
	smtp_client_command_callback_t *reset_callback, void *reset_context);
#define smtp_client_transaction_reset(trans, reset_callback, reset_context) \
	smtp_client_transaction_reset(trans, \
		(smtp_client_command_callback_t *)reset_callback, \
		reset_context + CALLBACK_TYPECHECK(reset_callback, void (*)( \
			const struct smtp_reply *reply, typeof(reset_context))))

/* Return transaction statistics. */
const struct smtp_client_transaction_times *
smtp_client_transaction_get_times(struct smtp_client_transaction *trans);

/* Return transaction state */
enum smtp_client_transaction_state
smtp_client_transaction_get_state(struct smtp_client_transaction *trans)
	ATTR_PURE;
const char *
smtp_client_transaction_get_state_name(struct smtp_client_transaction *trans)
	ATTR_PURE;
const char *
smtp_client_transaction_get_state_destription(
	struct smtp_client_transaction *trans);

#endif
