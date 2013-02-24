/* Copyright (c) 2009-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "base64.h"
#include "str.h"
#include "llist.h"
#include "istream.h"
#include "ostream.h"
#include "hostpid.h"
#include "process-title.h"
#include "var-expand.h"
#include "settings-parser.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-storage-service.h"
#include "raw-storage.h"
#include "main.h"
#include "lda-settings.h"
#include "lmtp-settings.h"
#include "lmtp-proxy.h"
#include "commands.h"
#include "client.h"

#include <unistd.h>

#define CLIENT_IDLE_TIMEOUT_MSECS (1000*60*5)
#define CLIENT_MAX_INPUT_SIZE 4096

static struct client *clients = NULL;
unsigned int clients_count = 0;

void client_state_set(struct client *client, const char *name)
{
	client->state.name = name;

	if (!client->service_set->verbose_proctitle)
		return;
	if (clients_count == 0)
		process_title_set("[idling]");
	else if (clients_count > 1)
		process_title_set(t_strdup_printf("[%u clients]", clients_count));
	else
		process_title_set(t_strdup_printf("[%s]", client->state.name));
}

static void client_idle_timeout(struct client *client)
{
	client_destroy(client,
		       t_strdup_printf("421 4.4.2 %s", client->my_domain),
		       "Disconnected client for inactivity");
}

static int client_input_line(struct client *client, const char *line)
{
	const char *cmd, *args;

	args = strchr(line, ' ');
	if (args == NULL) {
		cmd = line;
		args = "";
	} else {
		cmd = t_strdup_until(line, args);
		args++;
	}
	cmd = t_str_ucase(cmd);

	if (strcmp(cmd, "LHLO") == 0)
		return cmd_lhlo(client, args);
	if (strcmp(cmd, "MAIL") == 0)
		return cmd_mail(client, args);
	if (strcmp(cmd, "RCPT") == 0)
		return cmd_rcpt(client, args);
	if (strcmp(cmd, "DATA") == 0)
		return cmd_data(client, args);
	if (strcmp(cmd, "QUIT") == 0)
		return cmd_quit(client, args);
	if (strcmp(cmd, "VRFY") == 0)
		return cmd_vrfy(client, args);
	if (strcmp(cmd, "RSET") == 0)
		return cmd_rset(client, args);
	if (strcmp(cmd, "NOOP") == 0)
		return cmd_noop(client, args);
	if (strcmp(cmd, "XCLIENT") == 0)
		return cmd_xclient(client, args);

	client_send_line(client, "502 5.5.2 Unknown command");
	return 0;
}

int client_input_read(struct client *client)
{
	client->last_input = ioloop_time;
	timeout_reset(client->to_idle);

	switch (i_stream_read(client->input)) {
	case -2:
		/* buffer full */
		client_destroy(client, "502 5.5.2",
			       "Disconnected: Input buffer full");
		return -1;
	case -1:
		/* disconnected */
		client_destroy(client, NULL, NULL);
		return -1;
	case 0:
		/* nothing new read */
		return 0;
	default:
		/* something was read */
		return 0;
	}
}

void client_input_handle(struct client *client)
{
	struct ostream *output;
	const char *line;
	int ret;

	output = client->output;
	o_stream_ref(output);
	o_stream_cork(output);
	while ((line = i_stream_next_line(client->input)) != NULL) {
		T_BEGIN {
			ret = client_input_line(client, line);
		} T_END;
		if (ret < 0)
			break;
	}
	o_stream_uncork(output);
	o_stream_unref(&output);
}

static void client_input(struct client *client)
{
	if (client_input_read(client) < 0)
		return;
	client_input_handle(client);
}

static void client_raw_user_create(struct client *client)
{
	void **sets;

	sets = master_service_settings_get_others(master_service);
	client->raw_mail_user =
		raw_storage_create_from_set(client->user_set_info, sets[0]);
}

static void client_read_settings(struct client *client)
{
	struct mail_storage_service_input input;
	const struct setting_parser_context *set_parser;
	struct lmtp_settings *lmtp_set;
	struct lda_settings *lda_set;
	const char *error;

	memset(&input, 0, sizeof(input));
	input.module = input.service = "lmtp";
	input.local_ip = client->local_ip;
	input.remote_ip = client->remote_ip;
	input.username = "";

	if (mail_storage_service_read_settings(storage_service, &input,
					       client->pool,
					       &client->user_set_info,
					       &set_parser, &error) < 0)
		i_fatal("%s", error);

	lmtp_settings_dup(set_parser, client->pool, &lmtp_set, &lda_set);
	settings_var_expand(&lmtp_setting_parser_info, lmtp_set, client->pool,
		mail_storage_service_get_var_expand_table(storage_service, &input));
	client->service_set = master_service_settings_get(master_service);
	client->lmtp_set = lmtp_set;
	client->set = lda_set;
}

static void client_generate_session_id(struct client *client)
{
	guid_128_t guid;
	string_t *id = t_str_new(30);

	guid_128_generate(guid);
	base64_encode(guid, sizeof(guid), id);
	i_assert(str_c(id)[str_len(id)-2] == '=');
	str_truncate(id, str_len(id)-2); /* drop trailing "==" */
	client->state.session_id = p_strdup(client->state_pool, str_c(id));
}

const char *client_remote_id(struct client *client)
{
	const char *addr;

	addr = net_ip2addr(&client->remote_ip);
	if (addr == NULL)
		addr = "local";
	return addr;
}

void client_io_reset(struct client *client)
{
	if (client->io != NULL)
		io_remove(&client->io);
	if (client->to_idle != NULL)
		timeout_remove(&client->to_idle);
	client->io = io_add(client->fd_in, IO_READ, client_input, client);
        client->last_input = ioloop_time;
	client->to_idle = timeout_add(CLIENT_IDLE_TIMEOUT_MSECS,
				      client_idle_timeout, client);
}

struct client *client_create(int fd_in, int fd_out,
			     const struct master_service_connection *conn)
{
	struct client *client;
	pool_t pool;

	/* always use nonblocking I/O */
	net_set_nonblock(fd_in, TRUE);
	net_set_nonblock(fd_out, TRUE);

	pool = pool_alloconly_create("lmtp client", 2048);
	client = p_new(pool, struct client, 1);
	client->pool = pool;
	client->fd_in = fd_in;
	client->fd_out = fd_out;
	client->remote_ip = conn->remote_ip;
	client->remote_port = conn->remote_port;
	(void)net_getsockname(conn->fd, &client->local_ip, &client->local_port);

	client->input = i_stream_create_fd(fd_in, CLIENT_MAX_INPUT_SIZE, FALSE);
	client->output = o_stream_create_fd(fd_out, (size_t)-1, FALSE);
	o_stream_set_no_error_handling(client->output, TRUE);

	client_io_reset(client);
	client->state_pool = pool_alloconly_create("client state", 4096);
	client->state.mail_data_fd = -1;
	client_read_settings(client);
	client_raw_user_create(client);
	client_generate_session_id(client);
	client->my_domain = client->set->hostname;
	client->lhlo = i_strdup("missing");
	client->proxy_ttl = LMTP_PROXY_DEFAULT_TTL;

	DLLIST_PREPEND(&clients, client);
	clients_count++;

	client_state_set(client, "banner");
	client_send_line(client, "220 %s %s", client->my_domain,
			 client->lmtp_set->login_greeting);
	i_info("Connect from %s", client_remote_id(client));
	return client;
}

void client_destroy(struct client *client, const char *prefix,
		    const char *reason)
{
	client_disconnect(client, prefix, reason);

	clients_count--;
	DLLIST_REMOVE(&clients, client);

	client_state_set(client, "destroyed");

	if (client->raw_mail_user != NULL)
		mail_user_unref(&client->raw_mail_user);
	if (client->proxy != NULL)
		lmtp_proxy_deinit(&client->proxy);
	if (client->io != NULL)
		io_remove(&client->io);
	if (client->to_idle != NULL)
		timeout_remove(&client->to_idle);
	i_stream_destroy(&client->input);
	o_stream_destroy(&client->output);

	net_disconnect(client->fd_in);
	if (client->fd_in != client->fd_out)
		net_disconnect(client->fd_out);
	client_state_reset(client);
	i_free(client->lhlo);
	pool_unref(&client->state_pool);
	pool_unref(&client->pool);

	master_service_client_connection_destroyed(master_service);
}

static const char *client_get_disconnect_reason(struct client *client)
{
	errno = client->input->stream_errno != 0 ?
		client->input->stream_errno :
		client->output->stream_errno;
	return errno == 0 || errno == EPIPE ? "Connection closed" :
		t_strdup_printf("Connection closed: %m");
}

void client_disconnect(struct client *client, const char *prefix,
		       const char *reason)
{
	if (client->disconnected)
		return;

	if (reason != NULL)
		client_send_line(client, "%s %s", prefix, reason);
	else
		reason = client_get_disconnect_reason(client);
	i_info("Disconnect from %s: %s (in %s)", client_remote_id(client),
	       reason, client->state.name);

	client->disconnected = TRUE;
}

void client_state_reset(struct client *client)
{
	struct mail_recipient *rcpt;

	if (client->proxy != NULL)
		lmtp_proxy_deinit(&client->proxy);

	if (array_is_created(&client->state.rcpt_to)) {
		array_foreach_modifiable(&client->state.rcpt_to, rcpt)
			mail_storage_service_user_free(&rcpt->service_user);
	}

	if (client->state.raw_mail != NULL) {
		struct mailbox_transaction_context *raw_trans =
			client->state.raw_mail->transaction;
		struct mailbox *raw_box = client->state.raw_mail->box;

		mail_free(&client->state.raw_mail);
		mailbox_transaction_rollback(&raw_trans);
		mailbox_free(&raw_box);
	}

	if (client->state.mail_data != NULL)
		buffer_free(&client->state.mail_data);
	if (client->state.mail_data_output != NULL)
		o_stream_unref(&client->state.mail_data_output);
	if (client->state.mail_data_fd != -1) {
		if (close(client->state.mail_data_fd) < 0)
			i_error("close(mail data fd) failed: %m");
	}

	memset(&client->state, 0, sizeof(client->state));
	p_clear(client->state_pool);
	client->state.mail_data_fd = -1;

	client_generate_session_id(client);
	client_state_set(client, "reset");
}

void client_send_line(struct client *client, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	T_BEGIN {
		string_t *str;

		str = t_str_new(256);
		str_vprintfa(str, fmt, args);
		str_append(str, "\r\n");
		o_stream_nsend(client->output, str_data(str), str_len(str));
	} T_END;
	va_end(args);
}

bool client_is_trusted(struct client *client)
{
	const char *const *net;
	struct ip_addr net_ip;
	unsigned int bits;

	if (client->lmtp_set->login_trusted_networks == NULL)
		return FALSE;

	net = t_strsplit_spaces(client->lmtp_set->login_trusted_networks, ", ");
	for (; *net != NULL; net++) {
		if (net_parse_range(*net, &net_ip, &bits) < 0) {
			i_error("login_trusted_networks: "
				"Invalid network '%s'", *net);
			break;
		}

		if (net_is_in_network(&client->remote_ip, &net_ip, bits))
			return TRUE;
	}
	return FALSE;
}

void clients_destroy(void)
{
	while (clients != NULL) {
		client_destroy(clients,
			t_strdup_printf("421 4.3.2 %s", clients->my_domain),
			"Shutting down");
	}
}
