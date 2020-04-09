/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "array.h"
#include "hostpid.h"
#include "llist.h"
#include "istream.h"
#include "ostream.h"
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
#include "master-auth.h"
#include "auth-client.h"
#include "dsasl-client.h"
#include "login-proxy.h"
#include "client-common.h"

struct client *clients = NULL;
static struct client *last_client = NULL;
static unsigned int clients_count = 0;

static struct client *client_fd_proxies = NULL;
static unsigned int client_fd_proxies_count = 0;

struct login_client_module_hooks {
	struct module *module;
	const struct login_client_hooks *hooks;
};

static ARRAY(struct login_client_module_hooks) module_hooks = ARRAY_INIT;

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
		secs = ioloop_time - client->auth_finished;
		user_reason = "Timeout while finishing login.";
		destroy_reason = t_strdup_printf(
			"Timeout while finishing login (waited %u secs)", secs);
		e_error(client->event, "%s", destroy_reason);
	} else if (client->auth_request != NULL) {
		user_reason =
			"Disconnected for inactivity during authentication.";
		destroy_reason =
			"Disconnected: Inactivity during authentication";
	} else if (client->login_proxy != NULL) {
		secs = ioloop_time - client->created;
		user_reason = "Timeout while finishing login.";
		destroy_reason = t_strdup_printf(
			"Logging in to %s:%u timed out "
			"(state=%s, duration=%us)",
			login_proxy_get_host(client->login_proxy),
			login_proxy_get_port(client->login_proxy),
			client_proxy_get_state(client), secs);
		e_error(login_proxy_get_event(client->login_proxy),
			"%s", destroy_reason);
	} else {
		user_reason = "Disconnected for inactivity.";
		destroy_reason = "Disconnected: Inactivity";
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
	     const struct master_service_ssl_settings *ssl_set)
{
	struct client *client;

	i_assert(fd != -1);

	client = login_binary->client_vfuncs->alloc(pool);
	client->v = *login_binary->client_vfuncs;
	if (client->v.auth_send_challenge == NULL)
		client->v.auth_send_challenge = client_auth_send_challenge;
	if (client->v.auth_parse_response == NULL)
		client->v.auth_parse_response = client_auth_parse_response;

	client->created = ioloop_time;
	client->refcount = 1;

	client->pool = pool;
	client->preproxy_pool = pool_alloconly_create(MEMPOOL_GROWING"preproxy pool", 256);
	client->set = set;
	client->ssl_set = ssl_set;
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
	client->trusted = client_is_trusted(client);

	if (conn->proxied) {
		client->proxied_ssl = conn->proxy.ssl;
		client->secured = conn->proxy.ssl || client->trusted;
		client->ssl_secured = conn->proxy.ssl;
		client->local_name = conn->proxy.hostname;
		client->client_cert_common_name = conn->proxy.cert_common_name;
	} else {
		client->secured = client->trusted ||
			net_ip_compare(&conn->real_remote_ip, &conn->real_local_ip);
	}
	client->proxy_ttl = LOGIN_PROXY_TTL;

	client->event = event_create(NULL);
	event_add_category(client->event, &login_binary->event_category);
	event_add_str(client->event, "local_ip", net_ip2addr(&conn->local_ip));
	event_add_int(client->event, "local_port", conn->local_port);
	event_add_str(client->event, "remote_ip", net_ip2addr(&conn->remote_ip));
	event_add_int(client->event, "remote_port", conn->remote_port);
	event_set_log_message_callback(client->event, client_log_msg_callback,
				       client);

	client_open_streams(client);
	return client;
}

void client_init(struct client *client, void **other_sets)
{
	if (last_client == NULL)
		last_client = client;
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

void client_disconnect(struct client *client, const char *reason)
{
	if (client->disconnected)
		return;
	client->disconnected = TRUE;

	if (!client->login_success &&
	    !client->no_extra_disconnect_reason && reason != NULL) {
		const char *extra_reason =
			client_get_extra_disconnect_reason(client);
		if (extra_reason[0] != '\0')
			reason = t_strconcat(reason, " ", extra_reason, NULL);
	}
	if (reason != NULL) {
		struct event *event = client->login_proxy == NULL ?
			client->event :
			login_proxy_get_event(client->login_proxy);
		e_info(event, "%s", reason);
	}

	if (client->output != NULL)
		o_stream_uncork(client->output);
	if (!client->login_success) {
		io_remove(&client->io);
		ssl_iostream_destroy(&client->ssl_iostream);
		iostream_proxy_unref(&client->iostream_fd_proxy);
		i_stream_close(client->input);
		o_stream_close(client->output);
		i_close_fd(&client->fd);
	} else {
		/* Login was successful. We may now be proxying the connection,
		   so don't disconnect the client until client_unref(). */
		if (client->iostream_fd_proxy != NULL) {
			client->fd_proxying = TRUE;
			i_assert(client->prev == NULL && client->next == NULL);
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
	/* remove from clients linked list before it's added to
	   client_fd_proxies. */
	DLLIST_REMOVE(&clients, client);

	client_disconnect(client, reason);

	pool_unref(&client->preproxy_pool);

	if (client->master_tag != 0) {
		i_assert(client->auth_request == NULL);
		i_assert(client->authenticating);
		i_assert(client->refcount > 1);
		client->authenticating = FALSE;
		master_auth_request_abort(master_auth, client->master_tag);
		client->refcount--;
	} else if (client->auth_request != NULL) {
		i_assert(client->authenticating);
		sasl_server_auth_abort(client);
	} else {
		i_assert(!client->authenticating);
	}

	timeout_remove(&client->to_disconnect);
	timeout_remove(&client->to_auth_waiting);
	str_free(&client->auth_response);

	if (client->proxy_password != NULL) {
		safe_memset(client->proxy_password, 0,
			    strlen(client->proxy_password));
		i_free_and_null(client->proxy_password);
	}

	if (client->proxy_sasl_client != NULL)
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
		DLLIST_REMOVE(&client_fd_proxies, client);
		i_assert(client_fd_proxies_count > 0);
		client_fd_proxies_count--;
	}
	i_stream_unref(&client->input);
	o_stream_unref(&client->output);
	i_close_fd(&client->fd);
	event_unref(&client->event);

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

void client_destroy_oldest(void)
{
	struct client *client;

	if (last_client == NULL) {
		/* we have no clients */
		return;
	}

	/* destroy the last client that hasn't successfully authenticated yet.
	   this is usually the last client, but don't kill it if it's just
	   waiting for master to finish its job. */
	for (client = last_client; client != NULL; client = client->prev) {
		if (client->master_tag == 0)
			break;
	}
	if (client == NULL)
		client = last_client;

	client_notify_disconnect(client, CLIENT_DISCONNECT_RESOURCE_CONSTRAINT,
				 "Connection queue full");
	client_destroy(client, "Disconnected: Connection queue full");
}

void clients_destroy_all_reason(const char *reason)
{
	struct client *client, *next;

	for (client = clients; client != NULL; client = next) {
		next = client->next;
		client_notify_disconnect(client,
			CLIENT_DISCONNECT_SYSTEM_SHUTDOWN, reason);
		client_destroy(client, reason);
	}
}

void clients_destroy_all(void)
{
	clients_destroy_all_reason("Disconnected: Shutting down");
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
					  &client->ssl_set, &other_sets);

	master_service_ssl_settings_to_iostream_set(client->ssl_set,
		pool_datastack_create(),
		MASTER_SERVICE_SSL_SETTINGS_TYPE_SERVER, &ssl_set);
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

	master_service_ssl_settings_to_iostream_set(client->ssl_set,
		pool_datastack_create(),
		MASTER_SERVICE_SSL_SETTINGS_TYPE_SERVER, &ssl_set);
	/* If the client cert is invalid, we'll reply NO to the login
	   command. */
	ssl_set.allow_invalid_cert = TRUE;
	if (ssl_iostream_server_context_cache_get(&ssl_set, &ssl_ctx, &error) < 0) {
		e_error(client->event,
			"Failed to initialize SSL server context: %s", error);
		return -1;
	}
	if (io_stream_create_ssl_server(ssl_ctx, &ssl_set,
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

	client->tls = TRUE;
	client->secured = TRUE;
	client->ssl_secured = TRUE;

	if (client->starttls) {
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
	client->starttls = TRUE;
	if (client_init_ssl(client) < 0) {
		client_notify_disconnect(client,
			CLIENT_DISCONNECT_INTERNAL_ERROR,
			"TLS initialization failed.");
		client_destroy(client,
			"Disconnected: TLS initialization failed.");
		return;
	}
	login_refresh_proctitle();

	client->v.starttls(client);
}

static int client_output_starttls(struct client *client)
{
	int ret;

	if ((ret = o_stream_flush(client->output)) < 0) {
		client_destroy(client, "Disconnected");
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
	if (client->tls) {
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

	if (!client->tls) {
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
	if (client->forward_fields == NULL)
		client->forward_fields = str_new(client->preproxy_pool, 32);
	else
		str_append_c(client->forward_fields, '\t');
	/* prefixing is done by auth process */
	str_append_tabescaped(client->forward_fields, key);
	str_append_c(client->forward_fields, '=');
	str_append_tabescaped(client->forward_fields, value);
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
	tab[5].value = net_ip2addr(&client->local_ip);
	tab[6].value = net_ip2addr(&client->ip);
	tab[7].value = my_pid;
	tab[8].value = client->auth_mech_name == NULL ? NULL :
		str_sanitize(client->auth_mech_name, MAX_MECH_NAME);
	tab[9].value = dec2str(client->local_port);
	tab[10].value = dec2str(client->remote_port);
	if (!client->tls) {
		tab[11].value = client->secured ? "secured" : NULL;
		tab[12].value = "";
	} else if (client->proxied_ssl) {
		tab[11].value = "TLS";
		tab[12].value = "(proxied)";
	} else {
		const char *ssl_state =
			ssl_iostream_is_handshaked(client->ssl_iostream) ?
			"TLS" : "TLS handshaking";
		const char *ssl_error =
			ssl_iostream_get_last_error(client->ssl_iostream);

		tab[11].value = ssl_error == NULL ? ssl_state :
			t_strdup_printf("%s: %s", ssl_state, ssl_error);
		tab[12].value =
			ssl_iostream_get_security_string(client->ssl_iostream);
	}
	tab[13].value = client->mail_pid == 0 ? "" :
		dec2str(client->mail_pid);
	tab[14].value = client_get_session_id(client);
	tab[15].value = net_ip2addr(&client->real_local_ip);
	tab[16].value = net_ip2addr(&client->real_remote_ip);
	tab[17].value = dec2str(client->real_local_port);
	tab[18].value = dec2str(client->real_remote_port);
	if (client->virtual_user_orig != NULL)
		get_var_expand_users(tab+19, client->virtual_user_orig);
	else {
		tab[19].value = tab[0].value;
		tab[20].value = tab[1].value;
		tab[21].value = tab[2].value;
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

static const char *
client_get_log_str(struct client *client, const char *msg)
{
	static const struct var_expand_func_table func_table[] = {
		{ "passdb", client_var_expand_func_passdb },
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

const char *client_get_extra_disconnect_reason(struct client *client)
{
	unsigned int auth_secs = client->auth_first_started == 0 ? 0 :
		ioloop_time - client->auth_first_started;

	if (client->set->auth_ssl_require_client_cert &&
	    client->ssl_iostream != NULL) {
		if (ssl_iostream_has_broken_client_cert(client->ssl_iostream))
			return "(client sent an invalid cert)";
		if (!ssl_iostream_has_valid_client_cert(client->ssl_iostream))
			return "(client didn't send a cert)";
	}

	if (!client->notified_auth_ready)
		return t_strdup_printf(
			"(disconnected before auth was ready, waited %u secs)",
			(unsigned int)(ioloop_time - client->created));

	if (client->auth_attempts == 0) {
		if (!client->banner_sent) {
			/* disconnected by a plugin */
			return "";
		}
		return t_strdup_printf("(no auth attempts in %u secs)",
			(unsigned int)(ioloop_time - client->created));
	}

	/* some auth attempts without SSL/TLS */
	if (client->set->auth_ssl_require_client_cert &&
	    client->ssl_iostream == NULL)
		return "(cert required, client didn't start TLS)";

	if (client->auth_waiting && client->auth_attempts == 1) {
		return t_strdup_printf("(client didn't finish SASL auth, "
				       "waited %u secs)", auth_secs);
	}
	if (client->auth_request != NULL && client->auth_attempts == 1) {
		return t_strdup_printf("(disconnected while authenticating, "
				       "waited %u secs)", auth_secs);
	}
	if (client->authenticating && client->auth_attempts == 1) {
		return t_strdup_printf("(disconnected while finishing login, "
				       "waited %u secs)", auth_secs);
	}
	if (client->auth_try_aborted && client->auth_attempts == 1)
		return "(aborted authentication)";
	if (client->auth_process_comm_fail)
		return "(auth process communication failure)";

	if (client->proxy_auth_failed)
		return "(proxy dest auth failed)";
	if (client->auth_successes > 0) {
		return t_strdup_printf("(internal failure, %u successful auths)",
				       client->auth_successes);
	}

	switch (client->last_auth_fail) {
	case CLIENT_AUTH_FAIL_CODE_AUTHZFAILED:
		return t_strdup_printf(
			"(authorization failed, %u attempts in %u secs)",
			client->auth_attempts, auth_secs);
	case CLIENT_AUTH_FAIL_CODE_TEMPFAIL:
		return "(auth service reported temporary failure)";
	case CLIENT_AUTH_FAIL_CODE_USER_DISABLED:
		return "(user disabled)";
	case CLIENT_AUTH_FAIL_CODE_PASS_EXPIRED:
		return "(password expired)";
	case CLIENT_AUTH_FAIL_CODE_INVALID_BASE64:
		return "(sent invalid base64 in response)";
	case CLIENT_AUTH_FAIL_CODE_LOGIN_DISABLED:
		return "(login disabled)";
	case CLIENT_AUTH_FAIL_CODE_MECH_INVALID:
		return "(tried to use unsupported auth mechanism)";
	case CLIENT_AUTH_FAIL_CODE_MECH_SSL_REQUIRED:
		return "(tried to use disallowed plaintext auth)";
	default:
		break;
	}

	return t_strdup_printf("(auth failed, %u attempts in %u secs)",
			       client->auth_attempts, auth_secs);
}

void client_notify_disconnect(struct client *client,
			      enum client_disconnect_reason reason,
			      const char *text)
{
	if (!client->notified_disconnect) {
		if (client->v.notify_disconnect != NULL)
			client->v.notify_disconnect(client, reason, text);
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
		client_destroy(client, "Disconnected: Input buffer full");
		return FALSE;
	case -1:
		/* disconnected */
		client_destroy(client, "Disconnected");
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
	array_free(&module_hooks);
}
