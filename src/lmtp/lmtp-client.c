/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lmtp-common.h"
#include "base64.h"
#include "str.h"
#include "llist.h"
#include "iostream.h"
#include "istream.h"
#include "ostream.h"
#include "hostpid.h"
#include "process-title.h"
#include "var-expand.h"
#include "module-dir.h"
#include "master-service-ssl.h"
#include "master-service-settings.h"
#include "iostream-ssl.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-storage-service.h"
#include "raw-storage.h"
#include "lda-settings.h"
#include "lmtp-local.h"
#include "lmtp-proxy.h"
#include "lmtp-commands.h"

#include <unistd.h>

#define CLIENT_IDLE_TIMEOUT_MSECS (1000*60*5)

static const struct smtp_server_callbacks lmtp_callbacks;
static const struct lmtp_client_vfuncs lmtp_client_vfuncs;
	
struct lmtp_module_register lmtp_module_register = { 0 };

static struct client *clients = NULL;
static unsigned int clients_count = 0;

static bool verbose_proctitle = FALSE;

static const char *client_remote_id(struct client *client)
{
	const char *addr;

	addr = net_ip2addr(&client->remote_ip);
	if (addr[0] == '\0')
		addr = "local";
	return addr;
}

static void refresh_proctitle(void)
{
	struct client *client;
	string_t *title;

	if (!verbose_proctitle)
		return;

	title = t_str_new(128);
	str_append_c(title, '[');
	switch (clients_count) {
	case 0:
		str_append(title, "idling");
		break;
	case 1:
		client = clients;
		str_append(title, client_remote_id(client));
		str_append_c(title, ' ');
		str_append(title, client_state_get_name(client));
		break;
	default:
		str_printfa(title, "%u connections", clients_count);
		break;
	}
	str_append_c(title, ']');
	process_title_set(str_c(title));
}

static void client_load_modules(struct client *client)
{
        struct module_dir_load_settings mod_set;

        i_zero(&mod_set);
        mod_set.abi_version = DOVECOT_ABI_VERSION;
        mod_set.require_init_funcs = TRUE;
        mod_set.binary_name = "lmtp";

        /* pre-load all configured mail plugins */
        mail_storage_service_modules =
                module_dir_load_missing(mail_storage_service_modules,
                                        client->lmtp_set->mail_plugin_dir,
                                        client->lmtp_set->mail_plugins,
                                        &mod_set);
	module_dir_init(mail_storage_service_modules);
}

static void client_raw_user_create(struct client *client)
{
	void **sets;

	sets = master_service_settings_get_others(master_service);
	client->raw_mail_user =
		raw_storage_create_from_set(client->user_set_info, sets[0]);
}

static void client_read_settings(struct client *client, bool ssl)
{
	struct mail_storage_service_input input;
	const struct setting_parser_context *set_parser;
	struct mail_user_settings *user_set;
	struct lmtp_settings *lmtp_set;
	struct lda_settings *lda_set;
	const char *error;

	i_zero(&input);
	input.module = input.service = "lmtp";
	input.local_ip = client->local_ip;
	input.remote_ip = client->remote_ip;
	input.local_port = client->local_port;
	input.remote_port = client->remote_port;
	input.conn_secured = ssl;
	input.conn_ssl_secured = ssl;
	input.username = "";

	if (mail_storage_service_read_settings(storage_service, &input,
					       client->pool,
					       &client->user_set_info,
					       &set_parser, &error) < 0)
		i_fatal("%s", error);

	lmtp_settings_dup(set_parser, client->pool,
			  &user_set, &lmtp_set, &lda_set);
	const struct var_expand_table *tab =
		mail_storage_service_get_var_expand_table(storage_service, &input);
	if (settings_var_expand(&lmtp_setting_parser_info, lmtp_set,
				client->pool, tab, &error) <= 0)
		i_fatal("Failed to expand settings: %s", error);
	client->service_set = master_service_settings_get(master_service);
	client->user_set = user_set;
	client->lmtp_set = lmtp_set;
	client->unexpanded_lda_set = lda_set;
}

struct client *client_create(int fd_in, int fd_out,
			     const struct master_service_connection *conn)
{
	struct smtp_server_settings lmtp_set;
	struct client *client;
	pool_t pool;

	pool = pool_alloconly_create("lmtp client", 2048);
	client = p_new(pool, struct client, 1);
	client->pool = pool;
	client->v = lmtp_client_vfuncs;
	client->remote_ip = conn->remote_ip;
	client->remote_port = conn->remote_port;
	client->local_ip = conn->local_ip;
	client->local_port = conn->local_port;
	client->state_pool = pool_alloconly_create("client state", 4096);

	client->event = event_create(NULL);
	event_add_category(client->event, &event_category_lmtp);

	client_read_settings(client, conn->ssl);
	client_raw_user_create(client);
	client_load_modules(client);
	client->my_domain = client->unexpanded_lda_set->hostname;

	if (client->service_set->verbose_proctitle)
		verbose_proctitle = TRUE;

	p_array_init(&client->module_contexts, client->pool, 5);

	i_zero(&lmtp_set);
	lmtp_set.capabilities =
		SMTP_CAPABILITY_PIPELINING |
		SMTP_CAPABILITY_ENHANCEDSTATUSCODES |
		SMTP_CAPABILITY_8BITMIME |
		SMTP_CAPABILITY_CHUNKING |
		SMTP_CAPABILITY_XCLIENT |
		SMTP_CAPABILITY__ORCPT;
	if (!conn->ssl && master_service_ssl_is_enabled(master_service))
		lmtp_set.capabilities |= SMTP_CAPABILITY_STARTTLS;
	lmtp_set.hostname = client->unexpanded_lda_set->hostname;
	lmtp_set.login_greeting = client->lmtp_set->login_greeting;
	lmtp_set.max_message_size = (uoff_t)-1;
	lmtp_set.rcpt_domain_optional = TRUE;
	lmtp_set.max_client_idle_time_msecs = CLIENT_IDLE_TIMEOUT_MSECS;
	lmtp_set.rawlog_dir = client->lmtp_set->lmtp_rawlog_dir;
	lmtp_set.event_parent = client->event;

	client->conn = smtp_server_connection_create
		(lmtp_server, fd_in, fd_out,
			&conn->remote_ip, conn->remote_port,
			conn->ssl, &lmtp_set, &lmtp_callbacks, client);

	DLLIST_PREPEND(&clients, client);
	clients_count++;

	e_info(client->event, "Connect from %s", client_remote_id(client));

	if (hook_client_created != NULL)
		hook_client_created(&client);

	smtp_server_connection_start(client->conn);

	refresh_proctitle();
	return client;
}

void client_state_reset(struct client *client)
{
	if (client->local != NULL)
		lmtp_local_deinit(&client->local);
	if (client->proxy != NULL)
		lmtp_proxy_deinit(&client->proxy);

	o_stream_unref(&client->state.mail_data_output);

	i_zero(&client->state);
	p_clear(client->state_pool);
}

void client_destroy(struct client *client, const char *enh_code,
		    const char *reason)
{
	client->v.destroy(client, enh_code, reason);
}

static void
client_default_destroy(struct client *client, const char *enh_code,
		       const char *reason)
{
	if (client->destroyed)
		return;
	client->destroyed = TRUE;

	client_disconnect(client, enh_code, reason);

	clients_count--;
	DLLIST_REMOVE(&clients, client);

	if (client->raw_mail_user != NULL)
		mail_user_unref(&client->raw_mail_user);

	client_state_reset(client);
	event_unref(&client->event);
	pool_unref(&client->state_pool);
	pool_unref(&client->pool);

	master_service_client_connection_destroyed(master_service);
}

const char *client_state_get_name(struct client *client)
{
	enum smtp_server_state state;

	if (client->conn == NULL)
		state = client->last_state;
	else
		state = smtp_server_connection_get_state(client->conn);
	return smtp_server_state_names[state];
}

void client_disconnect(struct client *client, const char *enh_code,
		       const char *reason)
{
	struct smtp_server_connection *conn = client->conn;

	if (client->disconnected)
		return;
	client->disconnected = TRUE;

	if (reason == NULL)
		reason = "Connection closed";
	e_info(client->event, "Disconnect from %s: %s (state=%s)",
	       client_remote_id(client), reason, client_state_get_name(client));

	if (conn != NULL) {
		client->last_state = smtp_server_connection_get_state(conn);
		smtp_server_connection_terminate(&conn,
			(enh_code == NULL ? "4.0.0" : enh_code), reason);
	}
}

static void
client_connection_trans_start(void *context,
			      struct smtp_server_transaction *trans)
{
	struct client *client = context;

	client->v.trans_start(client, trans);
}

static void
client_default_trans_start(struct client *client ATTR_UNUSED,
			   struct smtp_server_transaction *trans ATTR_UNUSED)
{
	/* nothing */
}

static void
client_connection_trans_free(void *context,
			     struct smtp_server_transaction *trans)
{
	struct client *client = (struct client *)context;

	client->v.trans_free(client, trans);
}

static void
client_default_trans_free(struct client *client,
			  struct smtp_server_transaction *trans ATTR_UNUSED)
{
	client_state_reset(client);
}

static void
client_connection_state_changed(void *context ATTR_UNUSED,
	enum smtp_server_state newstate ATTR_UNUSED)
{
	if (clients_count == 1)
		refresh_proctitle();
}

static void
client_connection_proxy_data_updated(void *context,
				     const struct smtp_proxy_data *data)
{
	struct client *client = (struct client *)context;

	client->remote_ip = data->source_ip;
	client->remote_port = data->source_port;

	if (clients_count == 1)
		refresh_proctitle();
}

static void client_connection_disconnect(void *context, const char *reason)
{
	struct client *client = (struct client *)context;
	struct smtp_server_connection *conn = client->conn;

	if (conn != NULL)
		client->last_state = smtp_server_connection_get_state(conn);
	client_disconnect(client, NULL, reason);
}

static void client_connection_destroy(void *context)
{
	struct client *client = (struct client *)context;

	client_destroy(client, NULL, NULL);
}

static bool client_connection_is_trusted(void *context)
{
	struct client *client = (struct client *)context;
	const char *const *net;
	struct ip_addr net_ip;
	unsigned int bits;

	if (client->lmtp_set->login_trusted_networks == NULL)
		return FALSE;

	net = t_strsplit_spaces(client->lmtp_set->login_trusted_networks, ", ");
	for (; *net != NULL; net++) {
		if (net_parse_range(*net, &net_ip, &bits) < 0) {
			e_error(client->event, "login_trusted_networks: "
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
		client_destroy(clients, "4.3.2", "Shutting down");
	}
}

static const struct smtp_server_callbacks lmtp_callbacks = {
	.conn_cmd_mail = cmd_mail,
	.conn_cmd_rcpt = cmd_rcpt,
	.conn_cmd_data_begin = cmd_data_begin,
	.conn_cmd_data_continue = cmd_data_continue,

	.conn_trans_start = client_connection_trans_start,
	.conn_trans_free = client_connection_trans_free,

	.conn_state_changed = client_connection_state_changed,

	.conn_proxy_data_updated = client_connection_proxy_data_updated,

	.conn_disconnect = client_connection_disconnect,
	.conn_destroy = client_connection_destroy,

	.conn_is_trusted = client_connection_is_trusted
};

static const struct lmtp_client_vfuncs lmtp_client_vfuncs = {
	.destroy = client_default_destroy,

	.trans_start = client_default_trans_start,
	.trans_free = client_default_trans_free,

	.cmd_mail = client_default_cmd_mail,
	.cmd_rcpt = client_default_cmd_rcpt,
	.cmd_data = client_default_cmd_data,

	.local_deliver = lmtp_local_default_deliver,
};
