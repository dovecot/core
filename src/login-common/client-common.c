/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "hex-binary.h"
#include "array.h"
#include "hostpid.h"
#include "llist.h"
#include "istream.h"
#include "md5.h"
#include "ostream.h"
#include "iostream.h"
#include "iostream-ssl.h"
#include "iostream-proxy.h"
#include "iostream-rawlog.h"
#include "process-title.h"
#include "hook-build.h"
#include "buffer.h"
#include "str.h"
#include "strescape.h"
#include "base64.h"
#include "str-sanitize.h"
#include "safe-memset.h"
#include "time-util.h"
#include "var-expand.h"
#include "master-interface.h"
#include "master-service.h"
#include "master-service-ssl-settings.h"
#include "login-client.h"
#include "anvil-client.h"
#include "auth-client.h"
#include "dsasl-client.h"
#include "login-proxy.h"
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

	if (client->set->login_trusted_networks == NULL)
		return FALSE;

	net = t_strsplit_spaces(client->set->login_trusted_networks, ", ");
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

struct client *
client_alloc(int fd, pool_t pool,
	     const struct master_service_connection *conn,
	     const struct login_settings *set,
	     const struct master_service_ssl_settings *ssl_set,
	     const struct master_service_ssl_server_settings *ssl_server_set)
{
	struct client *client;

	i_assert(fd != -1);

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
	client->set = set;
	client->ssl_set = ssl_set;
	client->ssl_server_set = ssl_server_set;
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
	event_add_str(client->event, "service", login_binary->protocol);
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
			strcmp(client->ssl_set->ssl, "required") != 0;
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
	} else if (net_ip_compare(&conn->real_remote_ip, &conn->real_local_ip)) {
		/* localhost connections are always secured */
		client->connection_secured = TRUE;
	} else if (client->connection_trusted &&
		   strcmp(client->ssl_set->ssl, "required") != 0) {
		/* Connections from login_trusted_networks are assumed to be
		   secured, except if ssl=required. */
		client->connection_secured = TRUE;
	}
	client->proxy_ttl = LOGIN_PROXY_TTL;


	client_open_streams(client);
	return client;
}

void client_init(struct client *client, void **other_sets)
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
	client->v.create(client, other_sets);
	client->create_finished = TRUE;

	if (auth_client_is_connected(auth_client))
		client_notify_auth_ready(client);
	else
		client_set_auth_waiting(client);

	login_refresh_proctitle();
}

static void client_disconnected_log(struct event *event, const char *reason,
				    bool add_disconnected_prefix)
{
	if (add_disconnected_prefix)
		e_info(event, "Disconnected: %s", reason);
	else
		e_info(event, "%s", reason);
}

static void login_aborted_event(struct client *client, const char *reason,
				bool add_disconnected_prefix)
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
	else
		event_reason = reason;

	e->add_str("reason", event_reason);
	e->add_int("auth_successes", client->auth_successes);
	e->add_int("auth_attempts", client->auth_attempts);
	e->add_int("auth_usecs", timeval_diff_usecs(&ioloop_timeval,
						    &client->auth_first_started));
	e->add_int("connected_usecs", timeval_diff_usecs(&ioloop_timeval,
							 &client->created));

	client_disconnected_log(e->event(), reason,
			        add_disconnected_prefix);
}

void client_disconnect(struct client *client, const char *reason,
		       bool add_disconnected_prefix)
{
	if (client->disconnected)
		return;
	client->disconnected = TRUE;

	if (reason == NULL) {
		/* proxying started */
	} else if (!client->login_success) {
		login_aborted_event(client, reason, add_disconnected_prefix);
	} else {
		client_disconnected_log(client->login_proxy == NULL ?
					client->event :
					login_proxy_get_event(client->login_proxy),
					reason, add_disconnected_prefix);
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

	client_disconnect(client, reason, !client->login_success);

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
	str_free(&client->auth_response);

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
	if (client_unref(&client) && initial_service_count == 1) {
		/* as soon as this connection is done with proxying
		   (or whatever), the process will die. there's no need for
		   authentication anymore, so close the connection.
		   do this only with initial service_count=1, in case there
		   are other clients with pending authentications */
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
	i_close_fd(&client->fd);
	event_unref(&client->event);
	event_unref(&client->event_auth);

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
	clients_destroy_all_reason("Shutting down");
}

static int client_sni_callback(const char *name, const char **error_r,
			       void *context)
{
	struct client *client = context;
	struct ssl_iostream_context *ssl_ctx;
	struct ssl_iostream_settings ssl_set;
	void **other_sets;
	const char *error;

	if (client->ssl_servername_settings_read)
		return 0;
	client->ssl_servername_settings_read = TRUE;

	client->local_name = p_strdup(client->pool, name);
	client->set = login_settings_read(client->pool, &client->local_ip,
					  &client->ip, name,
					  &client->ssl_set,
					  &client->ssl_server_set, &other_sets);

	master_service_ssl_server_settings_to_iostream_set(client->ssl_set,
		client->ssl_server_set, pool_datastack_create(), &ssl_set);
	if (ssl_iostream_server_context_cache_get(&ssl_set, &ssl_ctx, &error) < 0) {
		*error_r = t_strdup_printf(
			"Failed to initialize SSL server context: %s", error);
		return -1;
	}
	ssl_iostream_change_context(client->ssl_iostream, ssl_ctx);
	ssl_iostream_context_unref(&ssl_ctx);
	return 0;
}

int client_init_ssl(struct client *client)
{
	struct ssl_iostream_context *ssl_ctx;
	struct ssl_iostream_settings ssl_set;
	const char *error;

	i_assert(client->fd != -1);

	if (strcmp(client->ssl_set->ssl, "no") == 0) {
		e_info(client->event, "SSL is disabled (ssl=no)");
		return -1;
	}

	master_service_ssl_server_settings_to_iostream_set(client->ssl_set,
		client->ssl_server_set, pool_datastack_create(), &ssl_set);
	/* If the client cert is invalid, we'll reply NO to the login
	   command. */
	ssl_set.allow_invalid_cert = TRUE;
	if (ssl_iostream_server_context_cache_get(&ssl_set, &ssl_ctx, &error) < 0) {
		e_error(client->event,
			"Failed to initialize SSL server context: %s", error);
		return -1;
	}
	if (io_stream_create_ssl_server(ssl_ctx, &ssl_set, client->event,
					&client->input, &client->output,
					&client->ssl_iostream, &error) < 0) {
		e_error(client->event,
			"Failed to initialize SSL connection: %s", error);
		ssl_iostream_context_unref(&ssl_ctx);
		return -1;
	}
	ssl_iostream_context_unref(&ssl_ctx);
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
	client->connection_used_starttls = TRUE;
	if (client_init_ssl(client) < 0) {
		client_notify_disconnect(client,
			CLIENT_DISCONNECT_INTERNAL_ERROR,
			"TLS initialization failed.");
		client_destroy(client, "TLS initialization failed.");
		return;
	}
	login_refresh_proctitle();

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

	client_ref(client);
	client->iostream_fd_proxy =
		iostream_proxy_create(input, output,
				      client->input, client->output);
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

/* increment index if new proper login variables are added
 * make sure the aliases stay in the current order */
#define VAR_EXPAND_ALIAS_INDEX_START 28

static struct var_expand_table login_var_expand_empty_tab[] = {
	{ 'u', NULL, "user" },
	{ 'n', NULL, "username" },
	{ 'd', NULL, "domain" },

	{ 's', NULL, "service" },
	{ 'h', NULL, "home" },
	{ 'l', NULL, "lip" },
	{ 'r', NULL, "rip" },
	{ 'p', NULL, "pid" },
	{ 'm', NULL, "mech" },
	{ 'a', NULL, "lport" },
	{ 'b', NULL, "rport" },
	{ 'c', NULL, "secured" },
	{ 'k', NULL, "ssl_security" },
	{ 'e', NULL, "mail_pid" },
	{ '\0', NULL, "session" },
	{ '\0', NULL, "real_lip" },
	{ '\0', NULL, "real_rip" },
	{ '\0', NULL, "real_lport" },
	{ '\0', NULL, "real_rport" },
	{ '\0', NULL, "orig_user" },
	{ '\0', NULL, "orig_username" },
	{ '\0', NULL, "orig_domain" },
	{ '\0', NULL, "auth_user" },
	{ '\0', NULL, "auth_username" },
	{ '\0', NULL, "auth_domain" },
	{ '\0', NULL, "listener" },
	{ '\0', NULL, "local_name" },
	{ '\0', NULL, "ssl_ja3" },

	/* aliases: */
	{ '\0', NULL, "local_ip" },
	{ '\0', NULL, "remote_ip" },
	{ '\0', NULL, "local_port" },
	{ '\0', NULL, "remote_port" },
	{ '\0', NULL, "real_local_ip" },
	{ '\0', NULL, "real_remote_ip" },
	{ '\0', NULL, "real_local_port" },
	{ '\0', NULL, "real_remote_port" },
	{ '\0', NULL, "mechanism" },
	{ '\0', NULL, "original_user" },
	{ '\0', NULL, "original_username" },
	{ '\0', NULL, "original_domain" },

	{ '\0', NULL, NULL }
};

static void
get_var_expand_users(struct var_expand_table *tab, const char *user)
{
	unsigned int i;

	tab[0].value = user;
	tab[1].value = t_strcut(user, '@');
	tab[2].value = i_strchr_to_next(user, '@');

	for (i = 0; i < 3; i++)
		tab[i].value = str_sanitize(tab[i].value, 80);
}

static const struct var_expand_table *
get_var_expand_table(struct client *client)
{
	struct var_expand_table *tab;

	tab = t_malloc_no0(sizeof(login_var_expand_empty_tab));
	memcpy(tab, login_var_expand_empty_tab,
	       sizeof(login_var_expand_empty_tab));

	if (client->virtual_user != NULL)
		get_var_expand_users(tab, client->virtual_user);
	tab[3].value = login_binary->protocol;
	tab[4].value = getenv("HOME");
	tab[VAR_EXPAND_ALIAS_INDEX_START].value = tab[5].value =
		net_ip2addr(&client->local_ip);
	tab[VAR_EXPAND_ALIAS_INDEX_START + 1].value = tab[6].value =
		net_ip2addr(&client->ip);
	tab[7].value = my_pid;
	tab[VAR_EXPAND_ALIAS_INDEX_START + 8].value = tab[8].value =
		client->auth_mech_name == NULL ? NULL :
			str_sanitize(client->auth_mech_name, MAX_MECH_NAME);
	tab[VAR_EXPAND_ALIAS_INDEX_START + 2].value = tab[9].value =
		dec2str(client->local_port);
	tab[VAR_EXPAND_ALIAS_INDEX_START + 3].value = tab[10].value =
		dec2str(client->remote_port);
	if (client->haproxy_terminated_tls) {
		tab[11].value = "TLS";
		tab[12].value = "(proxied)";
	} else if (!client->connection_tls_secured) {
		tab[11].value = client->connection_secured ? "secured" : NULL;
		tab[12].value = "";
	} else if (client->ssl_iostream != NULL) {
		const char *ssl_state =
			ssl_iostream_is_handshaked(client->ssl_iostream) ?
			"TLS" : "TLS handshaking";
		const char *ssl_error =
			ssl_iostream_get_last_error(client->ssl_iostream);

		tab[11].value = ssl_error == NULL ? ssl_state :
			t_strdup_printf("%s: %s", ssl_state, ssl_error);
		tab[12].value =
			ssl_iostream_get_security_string(client->ssl_iostream);
		tab[27].value =
			ssl_iostream_get_ja3(client->ssl_iostream);
	} else {
		tab[11].value = "TLS";
		tab[12].value = "";
	}
	tab[13].value = client->mail_pid == 0 ? "" :
		dec2str(client->mail_pid);
	tab[14].value = client_get_session_id(client);
	tab[VAR_EXPAND_ALIAS_INDEX_START + 4].value = tab[15].value =
		net_ip2addr(&client->real_local_ip);
	tab[VAR_EXPAND_ALIAS_INDEX_START + 5].value = tab[16].value =
		net_ip2addr(&client->real_remote_ip);
	tab[VAR_EXPAND_ALIAS_INDEX_START + 6].value = tab[17].value =
		dec2str(client->real_local_port);
	tab[VAR_EXPAND_ALIAS_INDEX_START + 7].value = tab[18].value =
		dec2str(client->real_remote_port);
	if (client->virtual_user_orig != NULL)
		get_var_expand_users(tab+19, client->virtual_user_orig);
	else {
		tab[VAR_EXPAND_ALIAS_INDEX_START + 9].value = tab[19].value = tab[0].value;
		tab[VAR_EXPAND_ALIAS_INDEX_START + 10].value = tab[20].value = tab[1].value;
		tab[VAR_EXPAND_ALIAS_INDEX_START + 11].value = tab[21].value = tab[2].value;
	}
	if (client->virtual_auth_user != NULL)
		get_var_expand_users(tab+22, client->virtual_auth_user);
	else {
		tab[22].value = tab[19].value;
		tab[23].value = tab[20].value;
		tab[24].value = tab[21].value;
	}
	tab[25].value = client->listener_name;
	tab[26].value = str_sanitize(client->local_name, 256);
	return tab;
}

static bool have_username_key(const char *str)
{
	char key;

	for (; *str != '\0'; str++) {
		if (str[0] == '%' && str[1] != '\0') {
			str++;
			key = var_get_key(str);
			if (key == 'u' || key == 'n')
				return TRUE;
		}
	}
	return FALSE;
}

static int
client_var_expand_func_passdb(const char *data, void *context,
			      const char **value_r,
			      const char **error_r ATTR_UNUSED)
{
	struct client *client = context;
	const char *field_name = data;
	unsigned int i;
	size_t field_name_len;

	*value_r = NULL;

	if (client->auth_passdb_args == NULL)
		return 1;

	field_name_len = strlen(field_name);
	for (i = 0; client->auth_passdb_args[i] != NULL; i++) {
		if (strncmp(client->auth_passdb_args[i], field_name,
			    field_name_len) == 0 &&
		    client->auth_passdb_args[i][field_name_len] == '=') {
			*value_r = client->auth_passdb_args[i] + field_name_len+1;
			return 1;
		}
	}
	return 1;
}

static int client_var_expand_func_ssl_ja3_hash(const char *data ATTR_UNUSED,
					       void *context,
					       const char **value_r,
					       const char **error_r ATTR_UNUSED)
{
	struct client *client = context;

	if (client->ssl_iostream == NULL) {
		*value_r = NULL;
		return 1;
	}

	unsigned char hash[MD5_RESULTLEN];
	const char *ja3 = ssl_iostream_get_ja3(client->ssl_iostream);
	if (ja3 == NULL) {
		*value_r = NULL;
	} else {
		md5_get_digest(ja3, strlen(ja3), hash);
		*value_r = binary_to_hex(hash, sizeof(hash));
	}
	return 1;
}

static const char *
client_get_log_str(struct client *client, const char *msg)
{
	static const struct var_expand_func_table func_table[] = {
		{ "passdb", client_var_expand_func_passdb },
		{ "ssl_ja3_hash", client_var_expand_func_ssl_ja3_hash },
		{ NULL, NULL }
	};
	static bool expand_error_logged = FALSE;
	const struct var_expand_table *var_expand_table;
	char *const *e;
	const char *error;
	string_t *str, *str2;
	unsigned int pos;

	var_expand_table = get_var_expand_table(client);

	str = t_str_new(256);
	str2 = t_str_new(128);
	for (e = client->set->log_format_elements_split; *e != NULL; e++) {
		pos = str_len(str);
		if (var_expand_with_funcs(str, *e, var_expand_table,
					  func_table, client, &error) <= 0 &&
		    !expand_error_logged) {
			/* NOTE: Don't log via client->event - it would cause
			   recursion */
			i_error("Failed to expand log_format_elements=%s: %s",
				*e, error);
			expand_error_logged = TRUE;
		}
		if (have_username_key(*e)) {
			/* username is added even if it's empty */
		} else {
			str_truncate(str2, 0);
			if (var_expand(str2, *e, login_var_expand_empty_tab,
				       &error) <= 0) {
				/* we just logged this error above. no need
				   to do it again. */
			}
			if (strcmp(str_c(str)+pos, str_c(str2)) == 0) {
				/* empty %variables, don't add */
				str_truncate(str, pos);
				continue;
			}
		}

		if (str_len(str) > 0)
			str_append(str, ", ");
	}

	if (str_len(str) > 0)
		str_truncate(str, str_len(str)-2);

	const struct var_expand_table tab[3] = {
		{ 's', t_strdup(str_c(str)), NULL },
		{ '$', msg, NULL },
		{ '\0', NULL, NULL }
	};

	str_truncate(str, 0);
	if (var_expand(str, client->set->login_log_format, tab, &error) <= 0) {
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
	return login_ssl_initialized && strcmp(client->ssl_set->ssl, "no") != 0;
}

bool client_get_extra_disconnect_reason(struct client *client,
					const char **human_reason_r,
					const char **event_reason_r)
{
	unsigned int auth_secs = client->auth_first_started.tv_sec == 0 ? 0 :
		ioloop_time - client->auth_first_started.tv_sec;

	*event_reason_r = NULL;

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
	} else if (client->proxy_auth_failed) {
		/* Authentication to the next hop failed. */
		*event_reason_r = "proxy_dest_auth_failed";
		last_reason = "proxy dest auth failed";
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
	if (!client->notified_auth_ready) {
		if (client->v.notify_auth_ready != NULL)
			client->v.notify_auth_ready(client);
		client->notified_auth_ready = TRUE;
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
