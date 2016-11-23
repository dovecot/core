/* Copyright (c) 2009-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "istream.h"
#include "istream-concat.h"
#include "ostream.h"
#include "safe-mkstemp.h"
#include "index/raw/raw-storage.h"
#include "master-service.h"
#include "settings-parser.h"
#include "lda-settings.h"
#include "lmtp-settings.h"
#include "smtp-address.h"
#include "smtp-server.h"
#include "lmtp-proxy.h"
#include "lmtp-local.h"
#include "mail-deliver.h"
#include "mail-error.h"
#include "main.h"
#include "client.h"
#include "commands.h"

/*
 * EHLO command
 */

/*
 * STARTTLS command
 */

/*
 * MAIL command
 */

int cmd_mail(void *conn_ctx,
	     struct smtp_server_cmd_ctx *cmd ATTR_UNUSED,
	     struct smtp_server_cmd_mail *data ATTR_UNUSED)
{
	struct client *client = (struct client *)conn_ctx;

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
	     struct smtp_server_cmd_rcpt *data)
{
	struct client *client = (struct client *)conn_ctx;
	const char *username, *detail;
	char delim = '\0';
	int ret;

	smtp_address_detail_parse_temp(
		client->unexpanded_lda_set->recipient_delimiter,
		data->path, &username, &delim, &detail);
	if (client->lmtp_set->lmtp_proxy) {
		/* proxied? */
		if ((ret=lmtp_proxy_rcpt(client, cmd, data,
					 username, detail, delim)) != 0)
			return (ret < 0 ? -1 : 0);
		/* no */
	}

	/* local delivery */
	return lmtp_local_rcpt(client, cmd, data, username, detail);
}

/*
 * QUIT command
 */

/*
 * VRFY command
 */

/*
 * RSET command
 */

/*
 * NOOP command
 */

/*
 * DATA command
 */

static struct istream *cmd_data_get_input(struct client *client)
{
	struct client_state *state = &client->state;
	struct istream *input;

	if (state->mail_data_output != NULL) {
		o_stream_unref(&state->mail_data_output);
		input = i_stream_create_fd(state->mail_data_fd,
					   MAIL_READ_FULL_BLOCK_SIZE);
		i_stream_set_init_buffer_size(input,
					      MAIL_READ_FULL_BLOCK_SIZE);
	} else {
		input = i_stream_create_from_data(state->mail_data->data,
						  state->mail_data->used);
	}
	return input;
}

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
cmd_data_input_add_file(struct client *client,
			const unsigned char *data, size_t size)
{
	struct client_state *state = &client->state;
	string_t *path;
	int fd;

	if (state->mail_data_output != NULL) {
		/* continue writing to file */
		if (o_stream_send(state->mail_data_output,
				  data, size) != (ssize_t)size)
			return -1;
		return 0;
	}

	/* move everything to a temporary file. */
	path = t_str_new(256);
	mail_user_set_get_temp_prefix(path, client->raw_mail_user->set);
	fd = safe_mkstemp_hostpid(path, 0600, (uid_t)-1, (gid_t)-1);
	if (fd == -1) {
		i_error("Temp file creation to %s failed: %m", str_c(path));
		return -1;
	}

	/* we just want the fd, unlink it */
	if (i_unlink(str_c(path)) < 0) {
		/* shouldn't happen.. */
		i_close_fd(&fd);
		return -1;
	}

	state->mail_data_fd = fd;
	state->mail_data_output = o_stream_create_fd_file(fd, 0, FALSE);
	o_stream_set_name(state->mail_data_output, str_c(path));
	o_stream_cork(state->mail_data_output);

	o_stream_nsend(state->mail_data_output,
		       state->mail_data->data, state->mail_data->used);
	o_stream_nsend(client->state.mail_data_output, data, size);
	if (o_stream_flush(client->state.mail_data_output) < 0) {
		i_error("write(%s) failed: %s", str_c(path),
			o_stream_get_error(client->state.mail_data_output));
		return -1;
	}
	return 0;
}

static int
cmd_data_input_add(struct client *client,
		   const unsigned char *data, size_t size)
{
	if (client->state.mail_data->used + size <=
	    CLIENT_MAIL_DATA_MAX_INMEMORY_SIZE &&
	    client->state.mail_data_output == NULL) {
		buffer_append(client->state.mail_data, data, size);
		return 0;
	} else {
		return cmd_data_input_add_file(client, data, size);
	}
}

static int
cmd_data_finish(struct client *client,
		struct smtp_server_cmd_ctx *cmd,
		struct smtp_server_transaction *trans)
{
	struct client_state *state = &client->state;
	struct istream *input_msg, *input_local, *input_proxy;
	struct istream *inputs[3];

	client->state.data_end_timeval = ioloop_timeval;

	/* finish the message */
	input_msg = cmd_data_get_input(client);

	/* formulate prepended headers for both local and proxy delivery */
	cmd_data_create_added_headers(client, cmd, trans);

	/* construct message streams for local and proxy delivery */
	input_local = input_proxy = NULL;
	if (client->local != NULL) {
		inputs[0] = i_stream_create_from_data(
			state->added_headers_local,
			strlen(state->added_headers_local));
		inputs[1] = input_msg;
		inputs[2] = NULL;

		input_local = i_stream_create_concat(inputs);
		i_stream_set_name(input_local, "<lmtp DATA local>");
		i_stream_unref(&inputs[0]);
	}
	if (client->proxy != NULL) {
		inputs[0] = i_stream_create_from_data(
			state->added_headers_proxy,
			strlen(state->added_headers_proxy));
		inputs[1] = input_msg;
		inputs[2] = NULL;

		input_proxy = i_stream_create_concat(inputs);
		i_stream_set_name(input_proxy, "<lmtp DATA proxy>");
		i_stream_unref(&inputs[0]);
	}

	i_stream_unref(&input_msg);

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

int cmd_data_continue(void *conn_ctx, struct smtp_server_cmd_ctx *cmd,
		      struct smtp_server_transaction *trans)
{
	struct client *client = (struct client *)conn_ctx;
	struct istream *data_input = (struct istream *)trans->context;
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	i_assert(client->state.mail_data_output != NULL);

	while ((ret = i_stream_read(data_input)) > 0 || ret == -2) {
		data = i_stream_get_data(data_input, &size);
		if (cmd_data_input_add(client, data, size) < 0) {
			smtp_server_reply(cmd, 451, "4.3.0",
				"Temporary internal failure");
			return -1;
		}

		i_stream_skip(data_input, size);
	}

	if (ret == 0)
		return 0;
	if (ret < 0 && data_input->stream_errno != 0) {
		/* client probably disconnected */
		return -1;
	}

	/* the ending "." line was seen. finish delivery. */
	return cmd_data_finish(client, cmd, trans);
}

int cmd_data_begin(void *conn_ctx,
		   struct smtp_server_cmd_ctx *cmd,
		   struct smtp_server_transaction *trans,
		   struct istream *data_input)
{
	struct client *client = (struct client *)conn_ctx;

	i_assert(client->state.mail_data == NULL);
	client->state.mail_data = buffer_create_dynamic(default_pool, 1024*64);

	cmd->context = (void*)client;

	trans->context = (void*)data_input;
	return 0;
}

/*
 * XCLIENT command
 */
