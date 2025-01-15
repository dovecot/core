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
#include "module-dir.h"
#include "settings.h"
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
		str_append(title, smtp_server_state_names[client->state.state]);
		if (client->state.args != NULL && *client->state.args != '\0') {
			str_append_c(title, ' ');
			str_append(title, client->state.args);
		}
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

	if (!array_is_created(&client->lmtp_set->mail_plugins) ||
	    array_is_empty(&client->lmtp_set->mail_plugins))
		return;
        i_zero(&mod_set);
        mod_set.abi_version = DOVECOT_ABI_VERSION;
        mod_set.require_init_funcs = TRUE;
        mod_set.binary_name = "lmtp";

        /* pre-load all configured mail plugins */
        mail_storage_service_modules =
                module_dir_load_missing(mail_storage_service_modules,
                                        client->lmtp_set->mail_plugin_dir,
                                        settings_boollist_get(&client->lmtp_set->mail_plugins),
                                        &mod_set);
	module_dir_init(mail_storage_service_modules);
}

static void client_read_settings(struct client *client, bool ssl)
{
	struct mail_storage_service_input input;
	const char *error;

	i_zero(&input);
	input.service = "lmtp";
	input.local_ip = client->local_ip;
	input.remote_ip = client->remote_ip;
	input.local_port = client->local_port;
	input.remote_port = client->remote_port;
	input.end_client_tls_secured = ssl;
	input.username = "";

	client->set_instance = settings_instance_new(
		master_service_get_settings_root(master_service));
	event_set_ptr(client->event, SETTINGS_EVENT_INSTANCE,
		      client->set_instance);
	client->raw_mail_user =
		raw_storage_create_from_set(storage_service, client->set_instance);

	const struct var_expand_params *params =
		mail_storage_service_get_var_expand_params(storage_service, &input);

	struct event *event = event_create(client->event);
	event_set_ptr(event, SETTINGS_EVENT_VAR_EXPAND_PARAMS, (void *)params);
	if (settings_get(event, &lda_setting_parser_info, 0,
			 &client->lda_set, &error) < 0 ||
	    settings_get(event, &lmtp_setting_parser_info, 0,
			 &client->lmtp_set, &error) < 0)
		i_fatal("%s", error);
	event_unref(&event);
}

struct client *client_create(int fd_in, int fd_out,
			     const struct master_service_connection *conn)
{
	static const char *rcpt_param_extensions[] = {
		LMTP_RCPT_FORWARD_PARAMETER, NULL };
	static const struct smtp_capability_extra cap_rcpt_forward = {
		.name = LMTP_RCPT_FORWARD_CAPABILITY };
	enum lmtp_client_workarounds workarounds;
	struct smtp_server_settings lmtp_set;
	struct client *client;
	pool_t pool;
	bool conn_tls = conn->ssl || (conn->haproxied && conn->haproxy.ssl);

	pool = pool_alloconly_create("lmtp client", 2048);
	client = p_new(pool, struct client, 1);
	client->refcount = 1;
	client->pool = pool;
	client->v = lmtp_client_vfuncs;
	client->remote_ip = conn->remote_ip;
	client->remote_port = conn->remote_port;
	client->local_ip = conn->local_ip;
	client->local_port = conn->local_port;
	client->real_local_ip = conn->real_local_ip;
	client->real_local_port = conn->real_local_port;
	client->real_remote_ip = conn->real_remote_ip;
	client->real_remote_port = conn->real_remote_port;
	client->state_pool = pool_alloconly_create("client state", 4096);
	if (conn->haproxy.ssl)
		client->local_name = conn->haproxy.hostname;

	client->event = event_create(NULL);
	event_add_category(client->event, &event_category_lmtp);

	client_read_settings(client, conn_tls);
	client_load_modules(client);
	client->my_domain = p_strdup(client->pool, client->lda_set->hostname);

	if (master_service_get_service_settings(master_service)->verbose_proctitle)
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

#ifdef EXPERIMENTAL_MAIL_UTF8
	if (client->lmtp_set->mail_utf8_extensions)
		lmtp_set.capabilities |= SMTP_CAPABILITY_SMTPUTF8;
#endif
	if (!conn_tls && master_service_ssl_is_enabled(master_service))
		lmtp_set.capabilities |= SMTP_CAPABILITY_STARTTLS;
	lmtp_set.hostname = client->lda_set->hostname;
	lmtp_set.login_greeting = client->lmtp_set->login_greeting;
	lmtp_set.max_message_size = UOFF_T_MAX;
	lmtp_set.rcpt_param_extensions = rcpt_param_extensions;
	lmtp_set.rcpt_domain_optional = TRUE;
	lmtp_set.max_client_idle_time_msecs = CLIENT_IDLE_TIMEOUT_MSECS;
	lmtp_set.rawlog_dir = client->lmtp_set->lmtp_rawlog_dir;
	lmtp_set.event_parent = client->event;

	workarounds = client->lmtp_set->parsed_workarounds;
	if ((workarounds & LMTP_WORKAROUND_WHITESPACE_BEFORE_PATH) != 0) {
		lmtp_set.workarounds |=
			SMTP_SERVER_WORKAROUND_WHITESPACE_BEFORE_PATH;
	}
	if ((workarounds & LMTP_WORKAROUND_MAILBOX_FOR_PATH) != 0) {
		lmtp_set.workarounds |=
			SMTP_SERVER_WORKAROUND_MAILBOX_FOR_PATH;
	}

	client->conn = smtp_server_connection_create(
		lmtp_server, fd_in, fd_out,
		&conn->remote_ip, conn->remote_port, conn->ssl,
		&lmtp_set, &lmtp_callbacks, client);
	if (smtp_server_connection_is_trusted(client->conn)) {
		smtp_server_connection_add_extra_capability(
			client->conn, &cap_rcpt_forward);
	}

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
	i_free(client->state.args);

	if (client->local != NULL)
		lmtp_local_deinit(&client->local);
	if (client->proxy != NULL)
		lmtp_proxy_deinit(&client->proxy);

	o_stream_unref(&client->state.mail_data_output);

	i_zero(&client->state);
	p_clear(client->state_pool);
}

void client_ref(struct client *client)
{
	i_assert(client->refcount > 0);
	client->refcount++;
}

void client_unref(struct client **_client)
{
	struct client *client = *_client;

	if (client == NULL)
		return;
	*_client = NULL;

	i_assert(client->refcount > 0);
	if (--client->refcount > 0)
		return;

	client->v.destroy(client);
}

void client_destroy(struct client **_client, const char *enh_code,
		    const char *reason)
{
	struct client *client = *_client;
	struct smtp_server_connection *conn = client->conn;

	*_client = NULL;

	client_ref(client);
	smtp_server_connection_terminate(&conn,
		(enh_code == NULL ? "4.0.0" : enh_code), reason);
	/* smtp_server_connection_terminate() calls
	   client_connection_state_changed(), which may still access
	   client->conn. Don't clear it before that. */
	client->conn = NULL;
	client_unref(&client);
}

static void
client_default_destroy(struct client *client)
{
	if (client->destroyed)
		return;
	client->destroyed = TRUE;

	clients_count--;
	DLLIST_REMOVE(&clients, client);

	if (client->raw_mail_user != NULL)
		mail_user_deinit(&client->raw_mail_user);

	client_state_reset(client);

	settings_instance_free(&client->set_instance);
	settings_free(client->lda_set);
	settings_free(client->lmtp_set);
	event_unref(&client->event);
	pool_unref(&client->state_pool);
	pool_unref(&client->pool);

	master_service_client_connection_destroyed(master_service);
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
	struct client *client = context;

	client->v.trans_free(client, trans);
}

static void
client_default_trans_free(struct client *client,
			  struct smtp_server_transaction *trans ATTR_UNUSED)
{
	client_state_reset(client);
}

static void
client_connection_state_changed(void *context,
				enum smtp_server_state new_state,
				const char *new_args)
{
	struct client *client = context;

	i_free(client->state.args);

	client->state.state = new_state;
	client->state.args = i_strdup(new_args);

	if (client->local_name == NULL) {
		const char *local_name =
			smtp_server_connection_get_server_name(client->conn);
		client->local_name = p_strdup(client->pool, local_name);
	}
	if (clients_count == 1)
		refresh_proctitle();
}

void client_update_data_state(struct client *client, const char *new_args)
{
	i_assert(client->state.state == SMTP_SERVER_STATE_DATA);
	i_free(client->state.args);
	client->state.args = i_strdup(new_args);

	if (clients_count == 1)
		refresh_proctitle();
}

static void
client_connection_proxy_data_updated(void *context,
				     const struct smtp_proxy_data *data)
{
	struct client *client = context;

	client->remote_ip = data->source_ip;
	client->remote_port = data->source_port;
	client->local_name = data->local_name;

	if (data->client_transport != NULL) {
		client->end_client_tls_secured = TRUE;
		client->end_client_tls_secured =
			str_begins_with(data->client_transport,
					CLIENT_TRANSPORT_TLS);
	}

	if (clients_count == 1)
		refresh_proctitle();
}

static int
client_connection_tls_sni_callback(void *context, const char *name,
				   const char **error_r)
{
	struct client *client = context;

	const struct lda_settings *old_lda_set = client->lda_set;
	const struct lmtp_settings *old_lmtp_set = client->lmtp_set;
	client->lda_set = NULL;
	client->lmtp_set = NULL;
	event_add_str(client->event, "local_name", name);
	if (settings_get(client->event, &lda_setting_parser_info, 0,
			 &client->lda_set, error_r) < 0 ||
	    settings_get(client->event, &lmtp_setting_parser_info, 0,
			 &client->lmtp_set, error_r) < 0) {
		settings_free(client->lda_set);
		settings_free(client->lmtp_set);
		client->lda_set = old_lda_set;
		client->lmtp_set = old_lmtp_set;
		return -1;
	}
	settings_free(old_lda_set);
	settings_free(old_lmtp_set);
	smtp_server_connection_set_greeting(client->conn,
					    client->lmtp_set->login_greeting);

	return 0;
}

static void client_connection_disconnect(void *context, const char *reason)
{
	struct client *client = context;

	if (client->disconnected)
		return;
	client->disconnected = TRUE;

	if (reason == NULL)
		reason = "Connection closed";
	e_info(client->event, "Disconnect from %s: %s",
	       client_remote_id(client), reason);
}

static void client_connection_free(void *context)
{
	struct client *client = context;

	client_unref(&client);
}

static bool client_connection_is_trusted(void *context)
{
	struct client *client = context;
	const char *const *net;
	struct ip_addr net_ip;
	unsigned int bits;

	net = settings_boollist_get(&client->lmtp_set->login_trusted_networks);
	for (; *net != NULL; net++) {
		if (net_parse_range(*net, &net_ip, &bits) < 0) {
			e_error(client->event, "login_trusted_networks: "
				"Invalid network '%s'", *net);
			break;
		}

		if (net_is_in_network(&client->real_remote_ip, &net_ip, bits))
			return TRUE;
	}
	return FALSE;
}

void clients_destroy(void)
{
	while (clients != NULL) {
		struct client *client = clients;
		client_destroy(&client, "4.3.2", MASTER_SERVICE_SHUTTING_DOWN_MSG);
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

	.conn_tls_sni_callback = client_connection_tls_sni_callback,

	.conn_disconnect = client_connection_disconnect,
	.conn_free = client_connection_free,

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
