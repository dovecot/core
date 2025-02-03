/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "hex-binary.h"
#include "array.h"
#include "llist.h"
#include "istream.h"
#include "md5.h"
#include "ostream.h"
#include "istream-multiplex.h"
#include "ostream-multiplex.h"
#include "iostream.h"
#include "iostream-ssl.h"
#include "iostream-proxy.h"
#include "iostream-rawlog.h"
#include "hook-build.h"
#include "buffer.h"
#include "str.h"
#include "strescape.h"
#include "base64.h"
#include "str-sanitize.h"
#include "safe-memset.h"
#include "time-util.h"
#include "settings.h"
#include "master-interface.h"
#include "master-service.h"
#include "login-client.h"
#include "auth-client.h"
#include "dsasl-client.h"
#include "login-proxy.h"
#include "settings-parser.h"
#include "client-common.h"

struct client *clients = NULL;
struct client *destroyed_clients = NULL;
static struct client *last_client = NULL;
static unsigned int clients_count = 0;

static struct client *client_fd_proxies = NULL;
static unsigned int client_fd_proxies_count = 0;

struct login_client_module_hooks {
	struct module *module;
	const struct login_client_hooks *hooks;
};

static ARRAY(struct login_client_module_hooks) module_hooks = ARRAY_INIT;
static const char *client_auth_fail_code_reasons[] = {
	NULL,
	"authorization failed",
	"auth service reported temporary failure",
	"user disabled",
	"password expired",
	"sent invalid base64 in response",
	"login disabled",
	"tried to use unsupported auth mechanism",
	"tried to use disallowed cleartext auth",
	"anonymous logins disabled",
};
static_assert_array_size(client_auth_fail_code_reasons,
			 CLIENT_AUTH_FAIL_CODE_COUNT);

static const char *client_auth_fail_code_event_reasons[] = {
	NULL,
	"authorization_failed",
	"temp_fail",
	"user_disabled",
	"password_expired",
	"invalid_base64",
	"login_disabled",
	"invalid_mech",
	"cleartext_auth_disabled",
	"anonymous_auth_disabled",
};
static_assert_array_size(client_auth_fail_code_event_reasons,
			 CLIENT_AUTH_FAIL_CODE_COUNT);

static const char *client_get_log_str(struct client *client, const char *msg);
static const struct var_expand_params *
get_var_expand_params(struct client *client);
static void
client_var_expand_callback(void *context, struct var_expand_params *params_r);

void login_client_hooks_add(struct module *module,
			    const struct login_client_hooks *hooks)
{
	struct login_client_module_hooks *hook;

	hook = array_append_space(&module_hooks);
	hook->module = module;
	hook->hooks = hooks;
}

void login_client_hooks_remove(const struct login_client_hooks *hooks)
{
	const struct login_client_module_hooks *module_hook;
	unsigned int idx = UINT_MAX;

	array_foreach(&module_hooks, module_hook) {
		if (module_hook->hooks == hooks) {
			idx = array_foreach_idx(&module_hooks, module_hook);
			break;
		}
	}
	i_assert(idx != UINT_MAX);

	array_delete(&module_hooks, idx, 1);
}

static void hook_login_client_allocated(struct client *client)
{
	const struct login_client_module_hooks *module_hook;
	struct hook_build_context *ctx;

	ctx = hook_build_init((void *)&client->v, sizeof(client->v));
	client->vlast = &client->v;
	array_foreach(&module_hooks, module_hook) {
		if (module_hook->hooks->client_allocated != NULL) T_BEGIN {
			module_hook->hooks->client_allocated(client);
			hook_build_update(ctx, client->vlast);
		} T_END;
	}
	client->vlast = NULL;
	hook_build_deinit(&ctx);
}

static void client_idle_disconnect_timeout(struct client *client)
{
	const char *user_reason, *destroy_reason;
	unsigned int secs;

	if (client->master_tag != 0) {
		secs = ioloop_time - client->auth_finished.tv_sec;
		user_reason = "Timeout while finishing login.";
		destroy_reason = t_strdup_printf(
			"Timeout while finishing login (waited %u secs)", secs);
		e_error(client->event, "%s", destroy_reason);
	} else if (client->auth_request != NULL) {
		user_reason =
			"Disconnected for inactivity during authentication.";
		destroy_reason = "Inactivity during authentication";
	} else if (client->login_proxy != NULL) {
		secs = ioloop_time - client->created.tv_sec;
		user_reason = "Timeout while finishing login.";
		destroy_reason = t_strdup_printf(
			"Logging in timed out "
			"(state=%s, duration=%us)",
			client_proxy_get_state(client), secs);
		e_error(login_proxy_get_event(client->login_proxy),
			"%s", destroy_reason);
	} else {
		user_reason = "Disconnected for inactivity.";
		destroy_reason = "Inactivity";
	}
	client_notify_disconnect(client, CLIENT_DISCONNECT_TIMEOUT, user_reason);
	client_destroy(client, destroy_reason);
}

static void client_open_streams(struct client *client)
{
	client->input = i_stream_create_fd(client->fd, LOGIN_MAX_INBUF_SIZE);
	client->output = o_stream_create_fd(client->fd, LOGIN_MAX_OUTBUF_SIZE);
	o_stream_set_no_error_handling(client->output, TRUE);

	if (login_rawlog_dir != NULL) {
		if (iostream_rawlog_create(login_rawlog_dir, &client->input,
					   &client->output) < 0)
			login_rawlog_dir = NULL;
	}
}

static const char *
client_log_msg_callback(struct client *client,
			enum log_type log_type ATTR_UNUSED,
			const char *message)
{
	return client_get_log_str(client, message);
}

static bool client_is_trusted(struct client *client)
{
	const char *const *net;
	struct ip_addr net_ip;
	unsigned int bits;

	net = settings_boollist_get(&client->set->login_trusted_networks);
	for (; *net != NULL; net++) {
		if (net_parse_range(*net, &net_ip, &bits) < 0) {
			e_error(client->event, "login_trusted_networks: "
				"Invalid network '%s'", *net);
			break;
		}

		if (net_is_in_network(&client->ip, &net_ip, bits))
			return TRUE;
	}
	return FALSE;
}

static void client_settings_free(struct client *client)
{
	settings_free(client->set);
	settings_free(client->ssl_set);
	settings_free(client->ssl_server_set);
}

static int client_settings_get(struct client *client, const char **error_r)
{
	i_assert(client->set == NULL);

	if (settings_get(client->event, &login_setting_parser_info,
			 0, &client->set, error_r) < 0 ||
	    ssl_server_settings_get(client->event, &client->ssl_set,
				    &client->ssl_server_set, error_r) < 0) {
		client_settings_free(client);
		return -1;
	}
	return 0;
}

static bool application_protocol_equals(const char *proto)
{
	/* If login binary has no application protocols configured
	   we accept whatever we get. */
	if (login_binary->application_protocols == NULL)
		return TRUE;
	return str_array_find(login_binary->application_protocols, proto);
}

int client_alloc(int fd, const struct master_service_connection *conn,
		 struct client **client_r)
{
	struct client *client;
	const char *error;

	i_assert(fd != -1);

	pool_t pool = pool_alloconly_create("login client", 8*1024);
	client = login_binary->client_vfuncs->alloc(pool);
	client->v = *login_binary->client_vfuncs;
	if (client->v.auth_send_challenge == NULL)
		client->v.auth_send_challenge = client_auth_send_challenge;
	if (client->v.auth_parse_response == NULL)
		client->v.auth_parse_response = client_auth_parse_response;

	client->created = ioloop_timeval;
	client->refcount = 1;

	client->pool = pool;
	client->preproxy_pool = pool_alloconly_create(MEMPOOL_GROWING"preproxy pool", 256);
	p_array_init(&client->module_contexts, client->pool, 5);

	client->fd = fd;
	client->local_ip = conn->local_ip;
	client->local_port = conn->local_port;
	client->ip = conn->remote_ip;
	client->remote_port = conn->remote_port;
	client->real_local_ip = conn->real_local_ip;
	client->real_local_port = conn->real_local_port;
	client->real_remote_ip = conn->real_remote_ip;
	client->real_remote_port = conn->real_remote_port;
	client->listener_name = p_strdup(client->pool, conn->name);
	/* This event must exist before client_is_trusted() is called */
	client->event = event_create(NULL);
	event_add_category(client->event, &login_binary->event_category);
	event_add_ip(client->event, "local_ip", &conn->local_ip);
	event_add_int(client->event, "local_port", conn->local_port);
	event_add_ip(client->event, "remote_ip", &conn->remote_ip);
	event_add_int(client->event, "remote_port", conn->remote_port);
	event_add_str(client->event, "protocol", login_binary->protocol);
	event_add_str(client->event, "service", master_service_get_name(master_service));
	settings_event_add_list_filter_name(client->event, "service",
		master_service_get_name(master_service));

	/* Get settings before using log callback */
	event_set_ptr(client->event, SETTINGS_EVENT_VAR_EXPAND_CALLBACK,
		      client_var_expand_callback);
	event_set_ptr(client->event, SETTINGS_EVENT_VAR_EXPAND_CALLBACK_CONTEXT,
		      client);
	/* Need to set local name here already so that settings filters work */
	if (conn->haproxied)
		event_add_str(client->event, "local_name", conn->haproxy.hostname);
	if (client_settings_get(client, &error) < 0) {
		e_error(client->event, "%s", error);
		event_unref(&client->event);
		pool_unref(&client->pool);
		return -1;
	}

	event_set_log_message_callback(client->event, client_log_msg_callback,
				       client);
	client->connection_trusted = client_is_trusted(client);

	if (conn->haproxied) {
		/* haproxy connections are always coming from
		   haproxy_trusted_networks, so we consider them secured.
		   However, ssl=required implies that the client connection is
		   expected to be secured either via TLS or because the client
		   is coming from localhost.  */
		client->connection_secured = conn->haproxy.ssl ||
			net_ip_compare(&conn->remote_ip, &conn->local_ip) ||
			strcmp(client->ssl_server_set->ssl, "required") != 0;
		/* Assume that the connection is also TLS secured if client
		   terminated TLS connections on haproxy. If haproxy isn't
		   running on localhost, the haproxy-Dovecot connection isn't
		   TLS secured. However, that's most likely an intentional
		   configuration and we should just consider the connection
		   TLS secured anyway. */
		client->connection_tls_secured = conn->haproxy.ssl;
		client->haproxy_terminated_tls = conn->haproxy.ssl;
		/* Start by assuming this is the end client connection.
		   Later on this can be overwritten. */
		client->end_client_tls_secured = conn->haproxy.ssl;
		client->local_name = conn->haproxy.hostname;
		client->client_cert_common_name = conn->haproxy.cert_common_name;
		/* Check that alpn matches. */
		if (conn->haproxy.alpn_size > 0) {
			const char *proto =
				t_strndup(conn->haproxy.alpn, conn->haproxy.alpn_size);
			if (!application_protocol_equals(proto)) {
				e_error(client->event, "HAproxy application protocol mismatch (requested '%s')",
					proto);
				event_unref(&client->event);
				pool_unref(&client->pool);
				return -1;
			}
		}
	} else if (net_ip_compare(&conn->real_remote_ip, &conn->real_local_ip)) {
		/* localhost connections are always secured */
		client->connection_secured = TRUE;
	} else if (client->connection_trusted &&
		   strcmp(client->ssl_server_set->ssl, "required") != 0) {
		/* Connections from login_trusted_networks are assumed to be
		   secured, except if ssl=required. */
		client->connection_secured = TRUE;
	}
	client->proxy_ttl = LOGIN_PROXY_TTL;


	client_open_streams(client);
	*client_r = client;
	return 0;
}

/* Perform one read to ensure TLS handshake is started. */
static void initial_client_read(struct client *client)
{
	if (client_read(client))
		io_remove(&client->io);
}

int client_init(struct client *client)
{
	if (last_client == NULL)
		last_client = client;
	client->list_type = CLIENT_LIST_TYPE_ACTIVE;
	DLLIST_PREPEND(&clients, client);
	clients_count++;

	client->to_disconnect =
		timeout_add(CLIENT_LOGIN_TIMEOUT_MSECS,
			    client_idle_disconnect_timeout, client);

	hook_login_client_allocated(client);
	if (client->v.create(client) < 0)
		return -1;
	client->create_finished = TRUE;
	/* Do not allow clients to start IO just yet, wait until
	   TLS handshake and auth client are finished. */
	i_assert(client->io == NULL);
	/* If we are deferring auth, create initial io for reading the
	   client to ensure we do TLS handshake. Otherwise we can start
	   with client_input. */
	if (client->defer_auth_ready) {
		client->io =
			io_add_istream(client->input, initial_client_read, client);
	} else if (!client_does_custom_io(client))
		client->io = io_add_istream(client->input, client_input, client);
	/* Ensure we start connecting to auth server right away. */
	client_notify_auth_ready(client);

	login_refresh_proctitle();
	return 0;
}

static void login_aborted_event(struct client *client, const char *reason)
{
	struct event *event = client->login_proxy == NULL ?
		client->event :
		login_proxy_get_event(client->login_proxy);
	struct event_passthrough *e = event_create_passthrough(event)->
		set_name("login_aborted");
	const char *human_reason, *event_reason;

	i_assert(reason != NULL);
	if (client_get_extra_disconnect_reason(client, &human_reason, &event_reason))
		reason = t_strdup_printf("%s (%s)", reason, human_reason);

	e->add_str("reason", event_reason != NULL ? event_reason : reason);
	e->add_int("auth_successes", client->auth_successes);
	e->add_int("auth_attempts", client->auth_attempts);
	e->add_int("auth_usecs", timeval_diff_usecs(&ioloop_timeval,
						    &client->auth_first_started));
	e->add_int("connected_usecs", timeval_diff_usecs(&ioloop_timeval,
							 &client->created));

	if (event_reason == NULL)
		e_info(e->event(), "Login aborted: %s", reason);
	else {
		e_info(e->event(), "Login aborted: %s (%s)",
		       reason, event_reason);
	}
}

void client_disconnect(struct client *client, const char *reason)
{
	if (client->disconnected)
		return;
	client->disconnected = TRUE;

	if (reason == NULL) {
		/* proxying started */
	} else if (!client->login_success) {
		login_aborted_event(client, reason);
	} else {
		e_info(client->login_proxy == NULL ? client->event :
		       login_proxy_get_event(client->login_proxy),
		       "%s", reason);
	}

	if (client->output != NULL)
		o_stream_uncork(client->output);
	if (!client->login_success) {
		bool unref = FALSE;

		io_remove(&client->io);
		ssl_iostream_destroy(&client->ssl_iostream);
		if (client->iostream_fd_proxy != NULL) {
			iostream_proxy_unref(&client->iostream_fd_proxy);
			unref = TRUE;
		}
		i_stream_close(client->input);
		o_stream_close(client->output);
		(void)shutdown(client->fd, SHUT_RDWR);

		i_close_fd(&client->fd);
		if (unref) {
			i_assert(client->refcount > 1);
			client_unref(&client);
		}
	} else {
		/* Login was successful. We may now be proxying the connection,
		   so don't disconnect the client until client_unref(). */
		if (client->iostream_fd_proxy != NULL) {
			i_assert(!client->fd_proxying);
			client->fd_proxying = TRUE;
			i_assert(client->list_type == CLIENT_LIST_TYPE_DESTROYED);
			DLLIST_REMOVE(&destroyed_clients, client);
			client->list_type = CLIENT_LIST_TYPE_FD_PROXY;
			DLLIST_PREPEND(&client_fd_proxies, client);
			client_fd_proxies_count++;
		}
	}
}

void client_destroy(struct client *client, const char *reason)
{
	i_assert(client->create_finished);

	if (client->destroyed)
		return;
	client->destroyed = TRUE;

	if (last_client == client)
		last_client = client->prev;
	/* move to destroyed_clients linked list before it's potentially
	   added to client_fd_proxies. */
	i_assert(!client->fd_proxying);
	i_assert(client->list_type == CLIENT_LIST_TYPE_ACTIVE);
	DLLIST_REMOVE(&clients, client);
	client->list_type = CLIENT_LIST_TYPE_DESTROYED;
	DLLIST_PREPEND(&destroyed_clients, client);

	client_disconnect(client, reason);

	pool_unref(&client->preproxy_pool);
	i_zero(&client->forward_fields);
	client->client_id = NULL;

	if (client->master_tag != 0) {
		i_assert(client->auth_request == NULL);
		i_assert(client->authenticating);
		i_assert(client->refcount > 1);
		client->authenticating = FALSE;
		login_client_request_abort(login_client_list,
					   client->master_tag);
		client->refcount--;
	} else if (client->auth_request != NULL ||
		   client->anvil_query != NULL) {
		i_assert(client->authenticating);
		sasl_server_auth_abort(client);
	}
	i_assert(!client->authenticating);
	i_assert(client->auth_request == NULL);
	i_assert(client->anvil_query == NULL);

	if (client->reauth_request != NULL) {
		struct auth_client_request *reauth_request =
			client->reauth_request;
		auth_client_request_abort(&reauth_request, "Aborted");
		/* callback sets this to NULL */
		i_assert(client->reauth_request == NULL);
	}

	timeout_remove(&client->to_disconnect);
	timeout_remove(&client->to_auth_waiting);
	timeout_remove(&client->to_notify_auth_ready);
	str_free(&client->auth_response);
	i_free(client->auth_conn_cookie);

	if (client->proxy_password != NULL) {
		safe_memset(client->proxy_password, 0,
			    strlen(client->proxy_password));
		i_free_and_null(client->proxy_password);
	}

	dsasl_client_free(&client->proxy_sasl_client);
	if (client->login_proxy != NULL)
		login_proxy_free(&client->login_proxy);
	if (client->v.destroy != NULL)
		client->v.destroy(client);
	if (client_unref(&client) && initial_restart_request_count == 1) {
		/* as soon as this connection is done with proxying
		   (or whatever), the process will die. there's no need for
		   authentication anymore, so close the connection.
		   do this only with initial restart_request_count=1, in case
		   there are other clients with pending authentications */
		auth_client_disconnect(auth_client, "unnecessary connection");
	}
	login_client_destroyed();
	login_refresh_proctitle();
}

void client_destroy_iostream_error(struct client *client)
{
	const char *reason =
		io_stream_get_disconnect_reason(client->input, client->output);
	client_destroy(client, reason);
}

void client_destroy_success(struct client *client, const char *reason)
{
	client->login_success = TRUE;
	client_destroy(client, reason);
}

void client_ref(struct client *client)
{
	client->refcount++;
}

bool client_unref(struct client **_client)
{
	struct client *client = *_client;

	*_client = NULL;

	i_assert(client->refcount > 0);
	if (--client->refcount > 0)
		return TRUE;

	if (!client->create_finished) {
		client_settings_free(client);
		i_stream_unref(&client->input);
		o_stream_unref(&client->output);
		pool_unref(&client->preproxy_pool);
		event_unref(&client->event);
		event_unref(&client->event_auth);
		pool_unref(&client->pool);
		return FALSE;
	}

	i_assert(client->destroyed);
	i_assert(client->login_proxy == NULL);

	if (client->v.free != NULL)
		client->v.free(client);

	ssl_iostream_destroy(&client->ssl_iostream);
	iostream_proxy_unref(&client->iostream_fd_proxy);
	if (client->fd_proxying) {
		i_assert(client->list_type == CLIENT_LIST_TYPE_FD_PROXY);
		DLLIST_REMOVE(&client_fd_proxies, client);
		i_assert(client_fd_proxies_count > 0);
		client_fd_proxies_count--;
	} else {
		i_assert(client->list_type == CLIENT_LIST_TYPE_DESTROYED);
		DLLIST_REMOVE(&destroyed_clients, client);
	}
	client->list_type = CLIENT_LIST_TYPE_NONE;
	i_stream_unref(&client->input);
	o_stream_unref(&client->output);
	o_stream_unref(&client->multiplex_orig_output);
	i_close_fd(&client->fd);
	event_unref(&client->event);
	event_unref(&client->event_auth);
	client_settings_free(client);

	i_free(client->proxy_user);
	i_free(client->proxy_master_user);
	i_free(client->virtual_user);
	i_free(client->virtual_user_orig);
	i_free(client->virtual_auth_user);
	i_free(client->auth_mech_name);
	i_free(client->master_data_prefix);
	pool_unref(&client->pool);

	i_assert(clients_count > 0);
	clients_count--;

	master_service_client_connection_destroyed(master_service);
	login_refresh_proctitle();
	return FALSE;
}

void client_common_default_free(struct client *client ATTR_UNUSED)
{
}

bool client_destroy_oldest(bool kill, struct timeval *created_r)
{
	struct client *client;

	if (last_client == NULL) {
		/* we have no clients */
		return FALSE;
	}

	/* destroy the last client that hasn't successfully authenticated yet.
	   this is usually the last client, but don't kill it if it's just
	   waiting for master to finish its job. Also prefer to kill clients
	   that can immediately be killed (i.e. refcount=1) */
	for (client = last_client; client != NULL; client = client->prev) {
		if (client->master_tag == 0 && client->refcount == 1)
			break;
	}
	if (client == NULL)
		client = last_client;

	*created_r = client->created;
	if (!kill)
		return TRUE;

	client_notify_disconnect(client, CLIENT_DISCONNECT_RESOURCE_CONSTRAINT,
				 "Connection queue full");
	client_ref(client);
	client_destroy(client, "Connection queue full");
	/* return TRUE only if the client was actually freed */
	i_assert(client->create_finished);
	return !client_unref(&client);
}

void clients_destroy_all_reason(const char *reason)
{
	struct client *client, *next;

	for (client = clients; client != NULL; client = next) T_BEGIN {
		next = client->next;
		client_notify_disconnect(client,
			CLIENT_DISCONNECT_SYSTEM_SHUTDOWN, reason);
		client_destroy(client, reason);
	} T_END;
}

void clients_destroy_all(void)
{
	clients_destroy_all_reason(MASTER_SERVICE_SHUTTING_DOWN_MSG);
}

int client_sni_callback(const char *name, const char **error_r,
			void *context)
{
	struct client *client = context;
	struct ssl_iostream_context *ssl_ctx;
	const struct ssl_iostream_settings *ssl_set;
	int ret;

	if (client->ssl_servername_settings_read)
		return 0;
	client->ssl_servername_settings_read = TRUE;

	const struct login_settings *old_set = client->set;
	const struct ssl_settings *old_ssl_set = client->ssl_set;
	const struct ssl_server_settings *old_ssl_server_set =
		client->ssl_server_set;
	client->set = NULL;
	client->ssl_set = NULL;
	client->ssl_server_set = NULL;

	/* Add local_name also to event. This is especially important to get
	   local_name { .. } config filters to work when looking up the settings
	   again. */
	event_add_str(client->event, "local_name", name);
	client->local_name = p_strdup(client->pool, name);
	if (client_settings_get(client, error_r) < 0 ||
	    (client->v.reload_config != NULL &&
	     client->v.reload_config(client, error_r) < 0)) {
		/* make sure settings are free'd if reload_config
		   callback fails. */
		client_settings_free(client);
		client->set = old_set;
		client->ssl_set = old_ssl_set;
		client->ssl_server_set = old_ssl_server_set;
		return -1;
	}
	settings_free(old_set);
	settings_free(old_ssl_set);
	settings_free(old_ssl_server_set);

	ssl_server_settings_to_iostream_set(client->ssl_set,
		client->ssl_server_set, &ssl_set);
	if ((ret = ssl_iostream_server_context_cache_get(ssl_set, &ssl_ctx, error_r)) < 0) {
		settings_free(ssl_set);
		return -1;
	}
	settings_free(ssl_set);
	if (ret > 0 && login_binary->application_protocols != NULL) {
		ssl_iostream_context_set_application_protocols(ssl_ctx,
			login_binary->application_protocols);
	}
	ssl_iostream_change_context(client->ssl_iostream, ssl_ctx);
	ssl_iostream_context_unref(&ssl_ctx);

	client->defer_auth_ready = FALSE;
	client->to_notify_auth_ready =
		timeout_add_short(0, client_notify_auth_ready, client);

	return 0;
}

int client_init_ssl(struct client *client)
{
	const char *error;

	i_assert(client->fd != -1);

	client->defer_auth_ready = TRUE;

	if (strcmp(client->ssl_server_set->ssl, "no") == 0) {
		e_info(client->event, "SSL is disabled (ssl=no)");
		return -1;
	}

	if (client->v.iostream_change_pre != NULL)
		client->v.iostream_change_pre(client);
	const struct ssl_iostream_server_autocreate_parameters parameters = {
		.event_parent = client->event,
		.application_protocols = login_binary->application_protocols,
	};
	int ret = io_stream_autocreate_ssl_server(&parameters,
						  &client->input, &client->output,
						  &client->ssl_iostream, &error);
	if (client->v.iostream_change_post != NULL)
		client->v.iostream_change_post(client);
	if (ret < 0) {
		e_error(client->event,
			"Failed to initialize SSL connection: %s", error);
		return -1;
	}
	ssl_iostream_set_sni_callback(client->ssl_iostream,
				      client_sni_callback, client);

	client->connection_tls_secured = TRUE;
	client->connection_secured = TRUE;
	if (!client->end_client_tls_secured_set)
		client->end_client_tls_secured = TRUE;

	if (client->connection_used_starttls) {
		io_remove(&client->io);
		if (!client_does_custom_io(client)) {
			client->io = io_add_istream(client->input,
						    client_input, client);
		}
	}
	return 0;
}

static void client_start_tls(struct client *client)
{
	bool add_multiplex_ostream = FALSE;

	if (client->multiplex_output != NULL) {
		/* restart multiplexing after TLS iostreams are set up */
		client_multiplex_output_stop(client);
		add_multiplex_ostream = TRUE;
	}
	client->connection_used_starttls = TRUE;
	if (client_init_ssl(client) < 0) {
		client_notify_disconnect(client,
			CLIENT_DISCONNECT_INTERNAL_ERROR,
			"TLS initialization failed.");
		client_destroy(client, "TLS initialization failed.");
		return;
	}
	login_refresh_proctitle();

	if (add_multiplex_ostream)
		client_multiplex_output_start(client);
	client->v.starttls(client);
}

static int client_output_starttls(struct client *client)
{
	int ret;

	if ((ret = o_stream_flush(client->output)) < 0) {
		client_destroy_iostream_error(client);
		return 1;
	}

	if (ret > 0) {
		o_stream_unset_flush_callback(client->output);
		client_start_tls(client);
	}
	return 1;
}

void client_cmd_starttls(struct client *client)
{
	if (client->connection_tls_secured) {
		client->v.notify_starttls(client, FALSE, "TLS is already active.");
		return;
	}

	if (!client_is_tls_enabled(client)) {
		client->v.notify_starttls(client, FALSE, "TLS support isn't enabled.");
		return;
	}

	/* remove input handler, SSL proxy gives us a new fd. we also have to
	   remove it in case we have to wait for buffer to be flushed */
	io_remove(&client->io);

	client->v.notify_starttls(client, TRUE, "Begin TLS negotiation now.");

	/* uncork the old fd */
	o_stream_uncork(client->output);

	if (o_stream_flush(client->output) <= 0) {
		/* the buffer has to be flushed */
		o_stream_set_flush_pending(client->output, TRUE);
		o_stream_set_flush_callback(client->output,
					    client_output_starttls, client);
	} else {
		client_start_tls(client);
	}
}

void client_multiplex_output_start(struct client *client)
{
	if (client->v.iostream_change_pre != NULL)
		client->v.iostream_change_pre(client);

	client->multiplex_output =
		o_stream_create_multiplex(client->output, LOGIN_MAX_OUTBUF_SIZE,
					  OSTREAM_MULTIPLEX_FORMAT_STREAM);
	client->multiplex_orig_output = client->output;
	client->output = client->multiplex_output;

	if (client->v.iostream_change_post != NULL)
		client->v.iostream_change_post(client);
}

void client_multiplex_output_stop(struct client *client)
{
	i_assert(client->multiplex_output != NULL);
	i_assert(client->multiplex_orig_output != NULL);

	if (client->v.iostream_change_pre != NULL)
		client->v.iostream_change_pre(client);

	i_assert(client->output == client->multiplex_output);
	o_stream_unref(&client->output);
	client->output = client->multiplex_orig_output;
	client->multiplex_output = NULL;
	client->multiplex_orig_output = NULL;

	if (client->v.iostream_change_post != NULL)
		client->v.iostream_change_post(client);
}

static void
iostream_fd_proxy_finished(enum iostream_proxy_side side ATTR_UNUSED,
			   enum iostream_proxy_status status ATTR_UNUSED,
			   struct client *client)
{
	/* Destroy the proxy now. The other side of the proxy is still
	   unfinished and we don't want to get back here and unreference
	   the client twice. */
	iostream_proxy_unref(&client->iostream_fd_proxy);
	client_unref(&client);
}

int client_get_plaintext_fd(struct client *client, int *fd_r, bool *close_fd_r)
{
	int fds[2];

	if (client->ssl_iostream == NULL) {
		/* Plaintext connection - We can send the fd directly to
		   the post-login process without any proxying. */
		*fd_r = client->fd;
		*close_fd_r = FALSE;
		return 0;
	}

	/* We'll have to start proxying from now on until either side
	   disconnects. Create a socketpair where login process is proxying on
	   one side and the other side is sent to the post-login process. */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
		e_error(client->event, "socketpair() failed: %m");
		return -1;
	}
	fd_set_nonblock(fds[0], TRUE);
	fd_set_nonblock(fds[1], TRUE);

	struct ostream *output = o_stream_create_fd(fds[0], IO_BLOCK_SIZE);
	struct istream *input =
		i_stream_create_fd_autoclose(&fds[0], IO_BLOCK_SIZE);
	o_stream_set_no_error_handling(output, TRUE);

	i_assert(client->io == NULL);
	struct ostream *client_output = client->output;
	if (client->multiplex_output != NULL) {
		/* The post-login process takes over handling the multiplex
		   stream. */
		i_assert(client_output == client->multiplex_output);
		client_output = client->multiplex_orig_output;
	}

	client_ref(client);
	client->iostream_fd_proxy =
		iostream_proxy_create(input, output,
				      client->input, client_output);
	i_stream_unref(&input);
	o_stream_unref(&output);

	iostream_proxy_set_completion_callback(client->iostream_fd_proxy,
					       iostream_fd_proxy_finished,
					       client);
	iostream_proxy_start(client->iostream_fd_proxy);

	*fd_r = fds[1];
	*close_fd_r = TRUE;
	return 0;
}

unsigned int clients_get_count(void)
{
	return clients_count;
}

unsigned int clients_get_fd_proxies_count(void)
{
	return client_fd_proxies_count;
}

struct client *clients_get_first_fd_proxy(void)
{
	return client_fd_proxies;
}

void client_add_forward_field(struct client *client, const char *key,
			      const char *value)
{
	if (!array_is_created(&client->forward_fields))
		p_array_init(&client->forward_fields, client->preproxy_pool, 8);
	/* prefixing is done by auth process */
	const char *entry =
		p_strdup_printf(client->preproxy_pool, "%s=%s", key, value);
	array_push_back(&client->forward_fields, &entry);
}

bool client_forward_decode_base64(struct client *client, const char *value)
{
	size_t value_len = strlen(value);
	string_t *str = t_str_new(MAX_BASE64_DECODED_SIZE(value_len));
	if (base64_decode(value, value_len, str) < 0)
		return FALSE;

	char **_fields = p_strsplit_tabescaped(client->preproxy_pool,
					       str_c(str));
	const char *const *fields = (const char *const *)_fields;
	unsigned int fields_count = str_array_length(fields);
	p_array_init(&client->forward_fields,
		     client->preproxy_pool, fields_count);
	array_append(&client->forward_fields, fields, fields_count);
	return TRUE;
}

const char *client_get_session_id(struct client *client)
{
	buffer_t *buf, *base64_buf;
	struct timeval tv;
	uint64_t timestamp;
	unsigned int i;

	if (client->session_id != NULL)
		return client->session_id;

	buf = t_buffer_create(24);
	base64_buf = t_buffer_create(24*2);

	i_gettimeofday(&tv);
	timestamp = tv.tv_usec + (long long)tv.tv_sec * 1000ULL*1000ULL;

	/* add lowest 48 bits of the timestamp. this gives us a bit less than
	   9 years until it wraps */
	for (i = 0; i < 48; i += 8)
		buffer_append_c(buf, (timestamp >> i) & 0xff);

	buffer_append_c(buf, client->remote_port & 0xff);
	buffer_append_c(buf, (client->remote_port >> 8) & 0xff);
	if (IPADDR_IS_V6(&client->ip))
		buffer_append(buf, &client->ip.u.ip6, sizeof(client->ip.u.ip6));
	else
		buffer_append(buf, &client->ip.u.ip4, sizeof(client->ip.u.ip4));
	base64_encode(buf->data, buf->used, base64_buf);
	client->session_id = p_strdup(client->pool, str_c(base64_buf));
	return client->session_id;
}

static struct var_expand_table login_var_expand_empty_tab[] = {
	{ .key = "user", .value = NULL },

	{ .key = "protocol", .value = NULL },
	{ .key = "home", .value = NULL },
	{ .key = "local_ip", .value = NULL },
	{ .key = "remote_ip", .value = NULL },
	{ .key = "mechanism", .value = NULL },
	{ .key = "local_port", .value = NULL },
	{ .key = "remote_port", .value = NULL },
	{ .key = "secured", .value = NULL },
	{ .key = "ssl_security", .value = NULL },
	{ .key = "mail_pid", .value = NULL },
	{ .key = "session", .value = NULL },
	{ .key = "real_local_ip", .value = NULL },
	{ .key = "real_remote_ip", .value = NULL },
	{ .key = "real_local_port", .value = NULL },
	{ .key = "real_remote_port", .value = NULL },
	{ .key = "original_user", .value = NULL },
	{ .key = "auth_user", .value = NULL },
	{ .key = "listener", .value = NULL },
	{ .key = "local_name", .value = NULL },
	{ .key = "ssl_ja3", .value = NULL },
	{ .key = "ssl_ja3_hash", .value = NULL },

	VAR_EXPAND_TABLE_END
};

static const char *
client_ssl_ja3_hash(struct client *client)
{
	if (client->ssl_iostream == NULL)
		return "";

	unsigned char hash[MD5_RESULTLEN];
	const char *ja3 = ssl_iostream_get_ja3(client->ssl_iostream);
	if (ja3 == NULL)
		return "";
	md5_get_digest(ja3, strlen(ja3), hash);
	return binary_to_hex(hash, sizeof(hash));
}

static int
client_var_expand_func_passdb(const char *field_name, const char **value_r,
			      void *context,
			      const char **error_r ATTR_UNUSED)
{
	struct client *client = context;
	unsigned int i;
	size_t field_name_len;

	*value_r = "";

	if (client->auth_passdb_args == NULL)
		return 0;

	field_name_len = strlen(field_name);
	for (i = 0; client->auth_passdb_args[i] != NULL; i++) {
		if (strncmp(client->auth_passdb_args[i], field_name,
			    field_name_len) == 0 &&
		    client->auth_passdb_args[i][field_name_len] == '=') {
			*value_r = client->auth_passdb_args[i] + field_name_len+1;
			break;
		}
	}
	return 0;
}

static const struct var_expand_provider client_common_providers[] = {
	{ .key = "passdb", client_var_expand_func_passdb },
	VAR_EXPAND_TABLE_END
};

static const struct var_expand_params *
get_var_expand_params(struct client *client)
{
	struct var_expand_table *tab;

	tab = t_malloc_no0(sizeof(login_var_expand_empty_tab));
	memcpy(tab, login_var_expand_empty_tab,
	       sizeof(login_var_expand_empty_tab));

	if (client->virtual_user != NULL) {
		var_expand_table_set_value(tab, "user",
				str_sanitize(client->virtual_user, 80));
	}
	var_expand_table_set_value(tab, "protocol", login_binary->protocol);
	var_expand_table_set_value(tab, "home", getenv("HOME"));
	var_expand_table_set_value(tab, "local_ip", net_ip2addr(&client->local_ip));
	var_expand_table_set_value(tab, "remote_ip", net_ip2addr(&client->ip));
	if (client->auth_mech_name != NULL)
		var_expand_table_set_value(tab, "mechanism",
			str_sanitize(client->auth_mech_name, MAX_MECH_NAME));
	var_expand_table_set_value(tab, "local_port", dec2str(client->local_port));
	var_expand_table_set_value(tab, "remote_port", dec2str(client->remote_port));
	if (client->haproxy_terminated_tls) {
		var_expand_table_set_value(tab, "secured", "TLS");
		var_expand_table_set_value(tab, "ssl_security", "(proxied)");
	} else if (!client->connection_tls_secured) {
		if (client->connection_secured)
			var_expand_table_set_value(tab, "secured", "secured");
	} else if (client->ssl_iostream != NULL) {
		const char *ssl_state =
			ssl_iostream_is_handshaked(client->ssl_iostream) ?
			"TLS" : "TLS handshaking";
		const char *ssl_error =
			ssl_iostream_get_last_error(client->ssl_iostream);
		if (ssl_error != NULL)
			ssl_state = t_strdup_printf("%s: %s", ssl_state, ssl_error);
		var_expand_table_set_value(tab, "secured", ssl_state);
		var_expand_table_set_value(tab, "ssl_security",
			ssl_iostream_get_security_string(client->ssl_iostream));
		var_expand_table_set_value(tab, "ssl_ja3",
			ssl_iostream_get_ja3(client->ssl_iostream));
		var_expand_table_set_value(tab, "ssl_ja3_hash",
			client_ssl_ja3_hash(client));
	} else {
		var_expand_table_set_value(tab, "secured", "TSL");
		var_expand_table_set_value(tab, "ssl_security", "");
	}

	const char *mail_pid = client->mail_pid == 0 ? "" :
		dec2str(client->mail_pid);
	var_expand_table_set_value(tab, "mail_pid", mail_pid);
	var_expand_table_set_value(tab, "session", client_get_session_id(client));
	var_expand_table_set_value(tab, "real_local_ip",
			net_ip2addr(&client->real_local_ip));
	var_expand_table_set_value(tab, "real_remote_ip",
			net_ip2addr(&client->real_local_ip));
	var_expand_table_set_value(tab, "real_local_port",
			dec2str(client->real_local_port));
	var_expand_table_set_value(tab, "real_remote_port",
			dec2str(client->real_remote_port));
	if (client->virtual_user_orig != NULL) {
		var_expand_table_set_value(tab, "original_user",
				str_sanitize(client->virtual_user_orig, 80));
	} else
		var_expand_table_copy(tab, "original_user", "user");

	if (client->virtual_auth_user != NULL) {
		var_expand_table_set_value(tab, "auth_user",
				str_sanitize(client->virtual_auth_user, 80));
	} else
		var_expand_table_copy(tab, "auth_user", "user");

	var_expand_table_set_value(tab, "listener", client->listener_name);
	var_expand_table_set_value(tab, "local_name",
				   str_sanitize(client->local_name, 256));

	struct var_expand_params *params = t_new(struct var_expand_params, 1);
	params->table = tab;
	params->providers = client_common_providers;
	params->context = client;

	return params;
}

static void
client_var_expand_callback(void *context, struct var_expand_params *params_r)
{
	struct client *client = context;
	const struct var_expand_params *params = get_var_expand_params(client);
	*params_r = *params;
}

static const char *
client_get_log_str(struct client *client, const char *msg)
{
	struct client empty_client;
	i_zero(&empty_client);
	const struct var_expand_params *params = get_var_expand_params(client);
	const struct var_expand_params empty_params = {
		.table = login_var_expand_empty_tab,
		.providers = client_common_providers,
		.context = &empty_client,
		.event = client->event,
	};
	static bool expand_error_logged = FALSE;
	char *const *e;
	const char *error;
	string_t *str, *str2;

	str = t_str_new(256);
	str2 = t_str_new(256);
	size_t pos = 0;
	for (e = client->set->log_format_elements_split; *e != NULL; e++) {
		pos = str->used;
		struct var_expand_program *prog;
		if (var_expand_program_create(*e, &prog, &error) < 0 ||
		    var_expand_program_execute(str, prog, params, &error) < 0) {
			if (!expand_error_logged) {
				/* NOTE: Don't log via client->event -
				   it would cause recursion. */
				i_error("Failed to expand log_format_elements=%s: %s",
					*e, error);
				expand_error_logged = TRUE;
			}
		}
		const char *const *vars = var_expand_program_variables(prog);
		if (str_array_find(vars, "user")) {
			/* username is added even if it's empty */
			var_expand_program_free(&prog);
		} else {
			str_truncate(str2, 0);
			int ret = var_expand_program_execute(str2, prog,
							     &empty_params, &error);
			var_expand_program_free(&prog);
			if (ret < 0 || strcmp(str_c(str)+pos, str_c(str2)) == 0) {
				/* we just logged this error above. no need
				   to do it again. */
				str_truncate(str, pos);
				continue;
			}
		}
		pos = str->used;
		if (str_len(str) > 0)
			str_append(str, ", ");
	}
	/* remove the trailing comma */
	str_truncate(str, pos);

	const struct var_expand_params params2 = {
		.table = (const struct var_expand_table[]){
			{ .key = "elements", .value = t_strdup(str_c(str)) },
			{ .key = "message", .value = msg, },
			VAR_EXPAND_TABLE_END
		},
		.event = client->event,
	};

	str_truncate(str, 0);
	if (var_expand(str, client->set->login_log_format, &params2,
			   &error) < 0) {
		/* NOTE: Don't log via client->event - it would cause
		   recursion */
		i_error("Failed to expand login_log_format=%s: %s",
			client->set->login_log_format, error);
		expand_error_logged = TRUE;
	}
	return str_c(str);
}

bool client_is_tls_enabled(struct client *client)
{
	return login_ssl_initialized &&
		strcmp(client->ssl_server_set->ssl, "no") != 0;
}

bool client_get_extra_disconnect_reason(struct client *client,
					const char **human_reason_r,
					const char **event_reason_r)
{
	unsigned int auth_secs = client->auth_first_started.tv_sec == 0 ? 0 :
		ioloop_time - client->auth_first_started.tv_sec;

	*event_reason_r = NULL;

	if (client->ssl_iostream != NULL &&
	    !ssl_iostream_is_handshaked(client->ssl_iostream)) {
		*event_reason_r = "tls_handshake_not_finished";
		*human_reason_r = "disconnected during TLS handshake";
		return TRUE;
	}

	if (!client->notified_auth_ready) {
		*event_reason_r = "auth_process_not_ready";
		*human_reason_r = t_strdup_printf(
			"disconnected before auth was ready, waited %u secs",
			(unsigned int)(ioloop_time - client->created.tv_sec));
		return TRUE;
	}

	if (client->shutting_down) {
		if (client->resource_constraint) {
			*event_reason_r = "process_full";
			*human_reason_r = "client_limit and process_limit was hit"
					 " and this login session was killed.";
		} else {
			*event_reason_r = "shutting_down";
			*human_reason_r = "The process is shutting down so the"
					 " login is aborted.";
		}
		return TRUE;
	}

	/* Check for missing client SSL certificates before auth attempts.
	   We may have advertised LOGINDISABLED, which would have prevented
	   client from even attempting to authenticate. */
	if (client->set->auth_ssl_require_client_cert) {
		if (client->ssl_iostream == NULL) {
			*event_reason_r = "client_ssl_not_started";
			*human_reason_r = "cert required, client didn't start TLS";
			return TRUE;
		}
		if (ssl_iostream_has_broken_client_cert(client->ssl_iostream)) {
			*event_reason_r = "client_ssl_cert_untrusted";
			*human_reason_r = "client sent an untrusted cert";
			return TRUE;
		}
		if (!ssl_iostream_has_valid_client_cert(client->ssl_iostream)) {
			*event_reason_r = "client_ssl_cert_missing";
			*human_reason_r = "client didn't send a cert";
			return TRUE;
		}
	}

	if (client->auth_attempts == 0) {
		if (!client->banner_sent) {
			/* disconnected by a plugin */
			return FALSE;
		}
		*event_reason_r = "no_auth_attempts";
		*human_reason_r = t_strdup_printf("no auth attempts in %u secs",
			(unsigned int)(ioloop_time - client->created.tv_sec));
		return TRUE;
	}

	const char *last_reason = NULL;
	if (client->auth_process_comm_fail) {
		*event_reason_r = "auth_process_comm_fail";
		last_reason = "auth process communication failure";
	} else if (client->auth_aborted_by_client) {
		*event_reason_r = "auth_aborted_by_client";
		last_reason = "auth aborted by client";
	} else if (client->auth_client_continue_pending) {
		*event_reason_r = "auth_waiting_client";
		last_reason = "client didn't finish SASL auth";
	} else if (client->auth_nologin_referral) {
		/* Referral was sent to the connecting client, which is
		   expected to be a trusted Dovecot proxy. There should be no
		   further auth attempts. */
		*event_reason_r = "auth_nologin_referral";
		last_reason = "auth referral";
	} else if (client->proxy_failed) {
		const char *event_reason;
		switch (client->proxy_last_failure) {
		case LOGIN_PROXY_FAILURE_TYPE_CONNECT:
			event_reason = "connect_failed";
			last_reason = "connection failed";
			break;
		case LOGIN_PROXY_FAILURE_TYPE_INTERNAL:
		case LOGIN_PROXY_FAILURE_TYPE_INTERNAL_CONFIG:
			event_reason = "internal_failure";
			last_reason = "internal failure";
			break;
		case LOGIN_PROXY_FAILURE_TYPE_REMOTE:
		case LOGIN_PROXY_FAILURE_TYPE_REMOTE_CONFIG:
			event_reason = "remote_failure";
			last_reason = "remote failure";
			break;
		case LOGIN_PROXY_FAILURE_TYPE_PROTOCOL:
			event_reason = "protocol_failure";
			last_reason = "protocol failure";
			break;
		case LOGIN_PROXY_FAILURE_TYPE_AUTH:
			event_reason = "auth_failed";
			last_reason = "authentication failure";
			break;
		case LOGIN_PROXY_FAILURE_TYPE_AUTH_TEMPFAIL:
			event_reason = "auth_temp_failed";
			last_reason = "temporary authentication failure";
			break;
		case LOGIN_PROXY_FAILURE_TYPE_AUTH_REDIRECT:
			event_reason = "redirected";
			last_reason = "redirected";
			break;
		default:
			i_unreached();
		}
		/* Authentication to the next hop failed. */
		*event_reason_r = t_strdup_printf("proxy_dest_%s", event_reason);
		last_reason = t_strdup_printf("proxy dest %s", last_reason);
	} else if (client->auth_login_limit_reached) {
		*event_reason_r = "connection_limit";
		last_reason = "connection limit reached";
	} else {
		*event_reason_r = client_auth_fail_code_event_reasons[client->last_auth_fail];
		last_reason = client_auth_fail_code_reasons[client->last_auth_fail];
	}

	if (last_reason != NULL)
		i_assert(*event_reason_r != NULL);
	else if (client->auth_successes > 0) {
		/* ideally we wouldn't get here with such an ambiguous reason */
		*event_reason_r = "internal_failure";
		last_reason = "internal failure";
	} else {
		*event_reason_r = "auth_failed";
		last_reason = "auth failed";
	}

	string_t *str = t_str_new(128);
	str_append(str, last_reason);
	if (client->auth_successes > 0) {
		str_printfa(str, ", %u/%u successful auths ",
			    client->auth_successes, client->auth_attempts);
	} else {
		str_printfa(str, ", %u attempts ", client->auth_attempts);
	}

	str_printfa(str, "in %u secs", auth_secs);
	*human_reason_r = str_c(str);
	i_assert(*event_reason_r != NULL);
	return TRUE;
}

void client_notify_disconnect(struct client *client,
			      enum client_disconnect_reason reason,
			      const char *text)
{
	if (!client->notified_disconnect) {
		if (client->v.notify_disconnect != NULL)
			client->v.notify_disconnect(client, reason, text);
		switch (reason) {
		case CLIENT_DISCONNECT_RESOURCE_CONSTRAINT:
			client->resource_constraint = TRUE;
			/* fall through */
		case CLIENT_DISCONNECT_SYSTEM_SHUTDOWN:
			client->shutting_down = TRUE;
			break;
		case CLIENT_DISCONNECT_TIMEOUT:
		case CLIENT_DISCONNECT_INTERNAL_ERROR:
			break;
		}
		client->notified_disconnect = TRUE;
	}
}

void client_notify_auth_ready(struct client *client)
{
	timeout_remove(&client->to_notify_auth_ready);
	if (client->notified_auth_ready)
		return;

	if (client->to_auth_waiting != NULL)
		return;
	if (auth_client_is_connected(auth_client)) {
		if (client->defer_auth_ready)
			return;
		io_remove(&client->io);
		if (client->v.notify_auth_ready != NULL)
			client->v.notify_auth_ready(client);
		client->notified_auth_ready = TRUE;
	} else {
		client_set_auth_waiting(client);
	}
}

void client_notify_status(struct client *client, bool bad, const char *text)
{
	if (client->v.notify_status != NULL)
		client->v.notify_status(client, bad, text);
}

void client_common_send_raw_data(struct client *client,
				 const void *data, size_t size)
{
	ssize_t ret;

	ret = o_stream_send(client->output, data, size);
	if (ret < 0 || (size_t)ret != size) {
		/* either disconnection or buffer full. in either case we want
		   this connection destroyed. however destroying it here might
		   break things if client is still tried to be accessed without
		   being referenced.. */
		i_stream_close(client->input);
	}
}

void client_send_raw_data(struct client *client, const void *data, size_t size)
{
	client->v.send_raw_data(client, data, size);
}

void client_send_raw(struct client *client, const char *data)
{
	client_send_raw_data(client, data, strlen(data));
}

bool client_read(struct client *client)
{
	switch (i_stream_read(client->input)) {
	case -2:
		/* buffer full */
		client_notify_disconnect(client,
			CLIENT_DISCONNECT_RESOURCE_CONSTRAINT,
			"Input buffer full, aborting");
		client_destroy(client, "Input buffer full");
		return FALSE;
	case -1:
		/* disconnected */
		client_destroy_iostream_error(client);
		return FALSE;
	case 0:
		/* nothing new read */
		return i_stream_get_data_size(client->input) > 0;
	default:
		/* something was read */
		return TRUE;
	}
}

void client_input(struct client *client)
{
	i_assert(client->v.input != NULL);
	client->v.input(client);
}

void client_common_init(void)
{
	i_array_init(&module_hooks, 32);
}

void client_destroy_fd_proxies(void)
{
	while (client_fd_proxies != NULL) {
		struct client *client = client_fd_proxies;
		client_unref(&client);
	}
	i_assert(client_fd_proxies_count == 0);
}

void client_common_deinit(void)
{
	i_assert(destroyed_clients == NULL);
	array_free(&module_hooks);
}
