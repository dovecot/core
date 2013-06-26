/* Copyright (c) 2002-2013 Dovecot authors, see the included COPYING file */

#include "login-common.h"
#include "hostpid.h"
#include "llist.h"
#include "istream.h"
#include "ostream.h"
#include "iostream-rawlog.h"
#include "process-title.h"
#include "buffer.h"
#include "str.h"
#include "base64.h"
#include "str-sanitize.h"
#include "safe-memset.h"
#include "var-expand.h"
#include "master-interface.h"
#include "master-service.h"
#include "master-service-ssl-settings.h"
#include "master-auth.h"
#include "auth-client.h"
#include "dsasl-client.h"
#include "login-proxy.h"
#include "ssl-proxy.h"
#include "client-common.h"

#include <stdlib.h>

struct client *clients = NULL, *last_client = NULL;
static unsigned int clients_count = 0;

static void client_idle_disconnect_timeout(struct client *client)
{
	const char *user_reason, *destroy_reason;
	unsigned int secs;

	if (client->master_tag != 0) {
		secs = ioloop_time - client->auth_finished;
		user_reason = "Timeout while finishing login.";
		destroy_reason = t_strdup_printf(
			"Timeout while finishing login (waited %u secs)", secs);
		client_log_err(client, destroy_reason);
	} else if (client->auth_request != NULL) {
		user_reason =
			"Disconnected for inactivity during authentication.";
		destroy_reason =
			"Disconnected: Inactivity during authentication";
	} else if (client->login_proxy != NULL) {
		secs = ioloop_time - client->created;
		user_reason = "Timeout while finishing login.";
		destroy_reason = t_strdup_printf(
			"proxy: Logging in to %s:%u timed out "
			"(state=%u, duration=%us)",
			login_proxy_get_host(client->login_proxy),
			login_proxy_get_port(client->login_proxy),
			client->proxy_state, secs);
		client_log_err(client, destroy_reason);
	} else {
		user_reason = "Disconnected for inactivity.";
		destroy_reason = "Disconnected: Inactivity";
	}
	client_notify_disconnect(client, CLIENT_DISCONNECT_TIMEOUT, user_reason);
	client_destroy(client, destroy_reason);
}

static void client_open_streams(struct client *client)
{
	client->input =
		i_stream_create_fd(client->fd, LOGIN_MAX_INBUF_SIZE, FALSE);
	client->output =
		o_stream_create_fd(client->fd, LOGIN_MAX_OUTBUF_SIZE, FALSE);
	o_stream_set_no_error_handling(client->output, TRUE);

	if (login_rawlog_dir != NULL) {
		if (iostream_rawlog_create(login_rawlog_dir, &client->input,
					   &client->output) < 0)
			login_rawlog_dir = NULL;
	}
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
			i_error("login_trusted_networks: "
				"Invalid network '%s'", *net);
			break;
		}

		if (net_is_in_network(&client->ip, &net_ip, bits))
			return TRUE;
	}
	return FALSE;
}

struct client *
client_create(int fd, bool ssl, pool_t pool,
	      const struct login_settings *set,
	      const struct master_service_ssl_settings *ssl_set,
	      void **other_sets,
	      const struct ip_addr *local_ip, const struct ip_addr *remote_ip)
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
	client->set = set;
	client->ssl_set = ssl_set;
	client->real_local_ip = client->local_ip = *local_ip;
	client->real_remote_ip = client->ip = *remote_ip;
	client->fd = fd;
	client->tls = ssl;
	client->trusted = client_is_trusted(client);
	client->secured = ssl || client->trusted ||
		net_ip_compare(remote_ip, local_ip);
	client->proxy_ttl = LOGIN_PROXY_TTL;

	if (last_client == NULL)
		last_client = client;
	DLLIST_PREPEND(&clients, client);
	clients_count++;

	client->to_disconnect =
		timeout_add(CLIENT_LOGIN_TIMEOUT_MSECS,
			    client_idle_disconnect_timeout, client);
	client_open_streams(client);

	client->v.create(client, other_sets);

	if (auth_client_is_connected(auth_client))
		client_notify_auth_ready(client);
	else
		client_set_auth_waiting(client);

	login_refresh_proctitle();
	return client;
}

void client_destroy(struct client *client, const char *reason)
{
	if (client->destroyed)
		return;
	client->destroyed = TRUE;

	if (!client->login_success && reason != NULL) {
		reason = t_strconcat(reason, " ",
			client_get_extra_disconnect_reason(client), NULL);
	}
	if (reason != NULL)
		client_log(client, reason);

	if (last_client == client)
		last_client = client->prev;
	DLLIST_REMOVE(&clients, client);

	if (client->input != NULL)
		i_stream_close(client->input);
	if (client->output != NULL)
		o_stream_close(client->output);

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

	if (client->io != NULL)
		io_remove(&client->io);
	if (client->to_disconnect != NULL)
		timeout_remove(&client->to_disconnect);
	if (client->to_auth_waiting != NULL)
		timeout_remove(&client->to_auth_waiting);
	if (client->auth_response != NULL)
		str_free(&client->auth_response);

	if (client->fd != -1) {
		net_disconnect(client->fd);
		client->fd = -1;
	}

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

void client_destroy_internal_failure(struct client *client)
{
	client_notify_disconnect(client, CLIENT_DISCONNECT_INTERNAL_ERROR,
		"Internal login failure. "
		"Refer to server log for more information.");
	client_destroy(client, t_strdup_printf(
		"Internal login failure (pid=%s id=%u)",
		my_pid, client->master_auth_id));
}

void client_ref(struct client *client)
{
	client->refcount++;
}

bool client_unref(struct client **_client)
{
	struct client *client = *_client;

	i_assert(client->refcount > 0);
	if (--client->refcount > 0)
		return TRUE;

	*_client = NULL;

	i_assert(client->destroyed);
	i_assert(client->login_proxy == NULL);

	if (client->ssl_proxy != NULL)
		ssl_proxy_free(&client->ssl_proxy);
	if (client->input != NULL)
		i_stream_unref(&client->input);
	if (client->output != NULL)
		o_stream_unref(&client->output);

	i_free(client->proxy_user);
	i_free(client->proxy_master_user);
	i_free(client->virtual_user);
	i_free(client->auth_mech_name);
	i_free(client->master_data_prefix);
	pool_unref(&client->pool);

	i_assert(clients_count > 0);
	clients_count--;

	master_service_client_connection_destroyed(master_service);
	login_refresh_proctitle();
	return FALSE;
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

static void client_start_tls(struct client *client)
{
	int fd_ssl;

	client_ref(client);
	if (!client_unref(&client) || client->destroyed)
		return;

	fd_ssl = ssl_proxy_alloc(client->fd, &client->ip, client->pool,
				 client->set, client->ssl_set,
				 &client->ssl_proxy);
	if (fd_ssl == -1) {
		client_notify_disconnect(client,
			CLIENT_DISCONNECT_INTERNAL_ERROR,
			"TLS initialization failed.");
		client_destroy(client,
			"Disconnected: TLS initialization failed.");
		return;
	}
	ssl_proxy_set_client(client->ssl_proxy, client);
	ssl_proxy_start(client->ssl_proxy);

	client->starttls = TRUE;
	client->tls = TRUE;
	client->secured = TRUE;
	login_refresh_proctitle();

	client->fd = fd_ssl;
	client->io = io_add(client->fd, IO_READ, client_input, client);
	i_stream_unref(&client->input);
	o_stream_unref(&client->output);
	client_open_streams(client);

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
	if (client->io != NULL)
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

unsigned int clients_get_count(void)
{
	return clients_count;
}

const char *client_get_session_id(struct client *client)
{
	buffer_t *buf, *base64_buf;
	struct timeval tv;
	uint64_t timestamp;
	unsigned int i;

	if (client->session_id != NULL)
		return client->session_id;

	buf = buffer_create_dynamic(pool_datastack_create(), 24);
	base64_buf = buffer_create_dynamic(pool_datastack_create(), 24*2);

	if (gettimeofday(&tv, NULL) < 0)
		i_fatal("gettimeofday(): %m");
	timestamp = tv.tv_usec + (long long)tv.tv_sec * 1000ULL*1000ULL;

	/* add lowest 48 bits of the timestamp. this gives us a bit less than
	   9 years until it wraps */
	for (i = 0; i < 48; i += 8)
		buffer_append_c(buf, (timestamp >> i) & 0xff);

	buffer_append_c(buf, client->remote_port & 0xff);
	buffer_append_c(buf, (client->remote_port >> 16) & 0xff);
#ifdef HAVE_IPV6
	if (IPADDR_IS_V6(&client->ip))
		buffer_append(buf, &client->ip.u.ip6, sizeof(client->ip.u.ip6));
	else
#endif
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
	{ '\0', NULL, NULL }
};

static const struct var_expand_table *
get_var_expand_table(struct client *client)
{
	struct var_expand_table *tab;
	unsigned int i;

	tab = t_malloc(sizeof(login_var_expand_empty_tab));
	memcpy(tab, login_var_expand_empty_tab,
	       sizeof(login_var_expand_empty_tab));

	if (client->virtual_user != NULL) {
		tab[0].value = client->virtual_user;
		tab[1].value = t_strcut(client->virtual_user, '@');
		tab[2].value = strchr(client->virtual_user, '@');
		if (tab[2].value != NULL) tab[2].value++;

		for (i = 0; i < 3; i++)
			tab[i].value = str_sanitize(tab[i].value, 80);
	}
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
	} else {
		const char *ssl_state =
			ssl_proxy_is_handshaked(client->ssl_proxy) ?
			"TLS" : "TLS handshaking";
		const char *ssl_error =
			ssl_proxy_get_last_error(client->ssl_proxy);

		tab[11].value = ssl_error == NULL ? ssl_state :
			t_strdup_printf("%s: %s", ssl_state, ssl_error);
		tab[12].value =
			ssl_proxy_get_security_string(client->ssl_proxy);
	}
	tab[13].value = client->mail_pid == 0 ? "" :
		dec2str(client->mail_pid);
	tab[14].value = client_get_session_id(client);
	tab[15].value = net_ip2addr(&client->real_local_ip);
	tab[16].value = net_ip2addr(&client->real_remote_ip);
	tab[17].value = dec2str(client->real_local_port);
	tab[18].value = dec2str(client->real_remote_port);
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

static const char *
client_get_log_str(struct client *client, const char *msg)
{
	static struct var_expand_table static_tab[3] = {
		{ 's', NULL, NULL },
		{ '$', NULL, NULL },
		{ '\0', NULL, NULL }
	};
	const struct var_expand_table *var_expand_table;
	struct var_expand_table *tab;
	char *const *e;
	string_t *str, *str2;
	unsigned int pos;

	var_expand_table = get_var_expand_table(client);

	tab = t_malloc(sizeof(static_tab));
	memcpy(tab, static_tab, sizeof(static_tab));

	str = t_str_new(256);
	str2 = t_str_new(128);
	for (e = client->set->log_format_elements_split; *e != NULL; e++) {
		pos = str_len(str);
		var_expand(str, *e, var_expand_table);
		if (have_username_key(*e)) {
			/* username is added even if it's empty */
		} else {
			str_truncate(str2, 0);
			var_expand(str2, *e, login_var_expand_empty_tab);
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

	tab[0].value = t_strdup(str_c(str));
	tab[1].value = msg;
	str_truncate(str, 0);

	var_expand(str, client->set->login_log_format, tab);
	return str_c(str);
}

void client_log(struct client *client, const char *msg)
{
	T_BEGIN {
		i_info("%s", client_get_log_str(client, msg));
	} T_END;
}

void client_log_err(struct client *client, const char *msg)
{
	T_BEGIN {
		i_error("%s", client_get_log_str(client, msg));
	} T_END;
}

void client_log_warn(struct client *client, const char *msg)
{
	T_BEGIN {
		i_warning("%s", client_get_log_str(client, msg));
	} T_END;
}

bool client_is_tls_enabled(struct client *client)
{
	return ssl_initialized && strcmp(client->ssl_set->ssl, "no") != 0;
}

const char *client_get_extra_disconnect_reason(struct client *client)
{
	unsigned int auth_secs = client->auth_first_started == 0 ? 0 :
		ioloop_time - client->auth_first_started;

	if (client->set->auth_ssl_require_client_cert &&
	    client->ssl_proxy != NULL) {
		if (ssl_proxy_has_broken_client_cert(client->ssl_proxy))
			return "(client sent an invalid cert)";
		if (!ssl_proxy_has_valid_client_cert(client->ssl_proxy))
			return "(client didn't send a cert)";
	}

	if (!client->notified_auth_ready)
		return t_strdup_printf(
			"(disconnected before auth was ready, waited %u secs)",
			(unsigned int)(ioloop_time - client->created));

	if (client->auth_attempts == 0) {
		return t_strdup_printf("(no auth attempts in %u secs)",
			(unsigned int)(ioloop_time - client->created));
	}

	/* some auth attempts without SSL/TLS */
	if (client->auth_tried_disabled_plaintext)
		return "(tried to use disallowed plaintext auth)";
	if (client->set->auth_ssl_require_client_cert &&
	    client->ssl_proxy == NULL)
		return "(cert required, client didn't start TLS)";
	if (client->auth_tried_unsupported_mech)
		return "(tried to use unsupported auth mechanism)";
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
	if (client->auth_user_disabled)
		return "(user disabled)";
	if (client->auth_pass_expired)
		return "(password expired)";
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

void client_send_raw_data(struct client *client, const void *data, size_t size)
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
		return TRUE;
	default:
		/* something was read */
		return TRUE;
	}
}

void client_input(struct client *client)
{
	client->v.input(client);
}
