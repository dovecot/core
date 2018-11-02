/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lmtp-common.h"
#include "str.h"
#include "istream.h"
#include "istream-concat.h"
#include "ostream.h"
#include "iostream-temp.h"
#include "master-service.h"
#include "settings-parser.h"
#include "lda-settings.h"
#include "mail-user.h"
#include "smtp-address.h"
#include "lmtp-recipient.h"
#include "lmtp-proxy.h"
#include "lmtp-local.h"
#include "mail-deliver.h"
#include "mail-error.h"
#include "commands.h"

/*
 * MAIL command
 */

int cmd_mail(void *conn_ctx,
	     struct smtp_server_cmd_ctx *cmd,
	     struct smtp_server_cmd_mail *data)
{
	struct client *client = (struct client *)conn_ctx;

	return client->v.cmd_mail(client, cmd, data);
}

int client_default_cmd_mail(struct client *client,
			    struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
			    struct smtp_server_cmd_mail *data ATTR_UNUSED)
{
	if (client->lmtp_set->lmtp_user_concurrency_limit > 0) {
		/* connect to anvil before dropping privileges */
		lmtp_anvil_init();
	}
	return 1;
}

/*
 * RCPT command
 */

int cmd_rcpt(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
	     struct smtp_server_recipient *rcpt)
{
	struct client *client = (struct client *)conn_ctx;
	struct lmtp_recipient *lrcpt;

	lrcpt = lmtp_recipient_create(client, rcpt);

	return client->v.cmd_rcpt(client, cmd, lrcpt);
}

int client_default_cmd_rcpt(struct client *client,
			    struct smtp_server_cmd_ctx *cmd,
			    struct lmtp_recipient *lrcpt)
{
	struct smtp_server_recipient *rcpt = lrcpt->rcpt;
	const char *username, *detail;
	char delim = '\0';
	int ret;


	smtp_address_detail_parse_temp(
		client->unexpanded_lda_set->recipient_delimiter,
		rcpt->path, &username, &delim, &detail);
	if (client->lmtp_set->lmtp_proxy) {
		/* proxied? */
		if ((ret=lmtp_proxy_rcpt(client, cmd, lrcpt,
					 username, detail, delim)) != 0)
			return (ret < 0 ? -1 : 0);
		/* no */
	}

	/* local delivery */
	return lmtp_local_rcpt(client, cmd, lrcpt, username, detail);
}

/*
 * DATA command
 */

static void
cmd_data_create_added_headers(struct client *client,
			      struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
			      struct smtp_server_transaction *trans)
{
	size_t proxy_offset = 0;
	string_t *str;

	str = t_str_new(512);

	/* headers for local deliveries only */
	if (client->local != NULL)
		lmtp_local_add_headers(client->local, trans, str);

	/* headers for local and proxied messages */
	proxy_offset = str_len(str);
	smtp_server_transaction_write_trace_record(str, trans);

	client->state.added_headers_local =
		p_strdup(client->state_pool, str_c(str));
	client->state.added_headers_proxy =
		client->state.added_headers_local + proxy_offset;
}

static int
cmd_data_finish(struct client *client,
		struct smtp_server_cmd_ctx *cmd,
		struct smtp_server_transaction *trans)
{
	struct client_state *state = &client->state;
	struct istream *input_msg;
	int ret;

	i_assert(HAS_ALL_BITS(trans->flags,
			      SMTP_SERVER_TRANSACTION_FLAG_REPLY_PER_RCPT));

	client->state.data_end_timeval = ioloop_timeval;

	/* finish the message */
	input_msg = iostream_temp_finish(&state->mail_data_output,
					 IO_BLOCK_SIZE);

	ret = client->v.cmd_data(client, cmd, trans,
				 input_msg, client->state.data_size);
	i_stream_unref(&input_msg);

	return ret;
}

int cmd_data_continue(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
		      struct smtp_server_transaction *trans)
{
	struct client *client = (struct client *)conn_ctx;
	struct client_state *state = &client->state;
	struct istream *data_input = state->data_input;
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	i_assert(state->mail_data_output != NULL);

	while ((ret = i_stream_read(data_input)) > 0 || ret == -2) {
		data = i_stream_get_data(data_input, &size);
		if (o_stream_send(state->mail_data_output,
			data, size) != (ssize_t)size) {
			i_error("write(%s) failed: %s",
				o_stream_get_name(state->mail_data_output),
				o_stream_get_error(state->mail_data_output));
			smtp_server_reply(cmd, 451, "4.3.0",
				"Temporary internal failure");
			return -1;
		}

		i_stream_skip(data_input, size);

		if (!smtp_server_cmd_data_check_size(cmd))
			return -1;
	}

	if (ret == 0)
		return 0;
	if (ret < 0 && data_input->stream_errno != 0) {
		/* client probably disconnected */
		return -1;
	}

	/* Current data stream position is the data size */
	client->state.data_size = data_input->v_offset;

	/* the ending "." line was seen. finish delivery. */
	return cmd_data_finish(client, cmd, trans);
}

int cmd_data_begin(void *conn_ctx,
		   struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
		   struct smtp_server_transaction *trans ATTR_UNUSED,
		   struct istream *data_input)
{
	struct client *client = (struct client *)conn_ctx;
	string_t *path;

	i_assert(client->state.mail_data_output == NULL);

	path = t_str_new(256);
	mail_user_set_get_temp_prefix(path, client->raw_mail_user->set);
	client->state.mail_data_output = 
		iostream_temp_create_named(str_c(path), 0, "(lmtp data)");

	client->state.data_input = data_input;
	return 0;
}

int client_default_cmd_data(struct client *client,
			    struct smtp_server_cmd_ctx *cmd,
			    struct smtp_server_transaction *trans,
			    struct istream *data_input,
			    uoff_t data_size ATTR_UNUSED)
{
	struct client_state *state = &client->state;
	struct istream *input_local, *input_proxy;
	struct istream *inputs[3];

	/* formulate prepended headers for both local and proxy delivery */
	cmd_data_create_added_headers(client, cmd, trans);

	/* construct message streams for local and proxy delivery */
	input_local = input_proxy = NULL;
	if (client->local != NULL) {
		inputs[0] = i_stream_create_from_data(
			state->added_headers_local,
			strlen(state->added_headers_local));
		inputs[1] = data_input;
		inputs[2] = NULL;

		input_local = i_stream_create_concat(inputs);
		i_stream_set_name(input_local, "<lmtp DATA local>");
		i_stream_unref(&inputs[0]);
	}
	if (client->proxy != NULL) {
		inputs[0] = i_stream_create_from_data(
			state->added_headers_proxy,
			strlen(state->added_headers_proxy));
		inputs[1] = data_input;
		inputs[2] = NULL;

		input_proxy = i_stream_create_concat(inputs);
		i_stream_set_name(input_proxy, "<lmtp DATA proxy>");
		i_stream_unref(&inputs[0]);
	}

	/* local delivery */
	if (client->local != NULL) {
		lmtp_local_data(client, cmd, trans, input_local);
		i_stream_unref(&input_local);
	}
	/* proxy delivery */
	if (client->proxy != NULL) {
		lmtp_proxy_data(client, cmd, trans, input_proxy);
		i_stream_unref(&input_proxy);
	}
	return 0;
}
