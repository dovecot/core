/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "hostpid.h"
#include "login-common.h"
#include "array.h"
#include "iostream.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "safe-memset.h"
#include "time-util.h"
#include "login-proxy.h"
#include "auth-client.h"
#include "dsasl-client.h"
#include "master-service-ssl-settings.h"
#include "client-common.h"

#define PROXY_FAILURE_MSG "Account is temporarily unavailable."
#define PROXY_DEFAULT_TIMEOUT_MSECS (1000*30)

/* If we've been waiting auth server to respond for over this many milliseconds,
   send a "waiting" message. */
#define AUTH_WAITING_TIMEOUT_MSECS (30*1000)
#define AUTH_WAITING_WARNING_TIMEOUT_MSECS (10*1000)

static void client_auth_failed(struct client *client)
{
	i_free_and_null(client->master_data_prefix);
	if (client->auth_response != NULL)
		str_truncate(client->auth_response, 0);

	if (client->auth_initializing || client->destroyed)
		return;

	if (client->io != NULL)
		io_remove(&client->io);

	client->io = io_add(client->fd, IO_READ, client_input, client);
	client_input(client);
}

static void client_auth_waiting_timeout(struct client *client)
{
	if (!client->notified_auth_ready) {
		client_log_warn(client, "Auth process not responding, "
				"delayed sending initial response (greeting)");
	}
	client_notify_status(client, FALSE, client->master_tag == 0 ?
			     AUTH_SERVER_WAITING_MSG : AUTH_MASTER_WAITING_MSG);
	timeout_remove(&client->to_auth_waiting);
}

void client_set_auth_waiting(struct client *client)
{
	i_assert(client->to_auth_waiting == NULL);
	client->to_auth_waiting =
		timeout_add(!client->notified_auth_ready ?
			    AUTH_WAITING_WARNING_TIMEOUT_MSECS :
			    AUTH_WAITING_TIMEOUT_MSECS,
			    client_auth_waiting_timeout, client);
}

static void alt_username_set(ARRAY_TYPE(const_string) *alt_usernames, pool_t pool,
			     const char *key, const char *value)
{
	char *const *fields;
	unsigned int i, count;

	fields = array_get(&global_alt_usernames, &count);
	for (i = 0; i < count; i++) {
		if (strcmp(fields[i], key) == 0)
			break;
	}
	if (i == count) {
		char *new_key = i_strdup(key);
		array_append(&global_alt_usernames, &new_key, 1);
	}

	value = p_strdup(pool, value);
	if (i < array_count(alt_usernames)) {
		array_idx_set(alt_usernames, i, &value);
		return;
	}

	/* array is NULL-terminated, so if there are unused fields in
	   the middle set them as "" */
	while (array_count(alt_usernames) < i) {
		const char *empty_str = "";
		array_append(alt_usernames, &empty_str, 1);
	}
	array_append(alt_usernames, &value, 1);
}

static void client_auth_parse_args(struct client *client, bool success,
				   const char *const *args,
				   struct client_auth_reply *reply_r)
{
	const char *key, *value, *p;
	ARRAY_TYPE(const_string) alt_usernames;

	t_array_init(&alt_usernames, 4);
	i_zero(reply_r);

	for (; *args != NULL; args++) {
		p = strchr(*args, '=');
		if (p == NULL) {
			key = *args;
			value = "";
		} else {
			key = t_strdup_until(*args, p);
			value = p + 1;
		}
		if (strcmp(key, "nologin") == 0)
			reply_r->nologin = TRUE;
		else if (strcmp(key, "proxy") == 0)
			reply_r->proxy = TRUE;
		else if (strcmp(key, "temp") == 0)
			reply_r->temp = TRUE;
		else if (strcmp(key, "authz") == 0)
			reply_r->authz_failure = TRUE;
		else if (strcmp(key, "user_disabled") == 0)
			client->auth_user_disabled = TRUE;
		else if (strcmp(key, "pass_expired") == 0)
			client->auth_pass_expired = TRUE;
		else if (strcmp(key, "reason") == 0)
			reply_r->reason = value;
		else if (strcmp(key, "host") == 0)
			reply_r->host = value;
		else if (strcmp(key, "hostip") == 0)
			reply_r->hostip = value;
		else if (strcmp(key, "source_ip") == 0)
			reply_r->source_ip = value;
		else if (strcmp(key, "port") == 0) {
			if (net_str2port(value, &reply_r->port) < 0) {
				i_error("Auth service returned invalid "
					"port number: %s", value);
			}
		} else if (strcmp(key, "destuser") == 0)
			reply_r->destuser = value;
		else if (strcmp(key, "pass") == 0)
			reply_r->password = value;
		else if (strcmp(key, "fingerprint") == 0)
			reply_r->fingerprint = value;
		else if (strcmp(key, "proxy_timeout") == 0) {
			if (str_to_uint(value, &reply_r->proxy_timeout_msecs) < 0) {
				i_error("BUG: Auth service returned invalid "
					"proxy_timeout value: %s", value);
			}
			reply_r->proxy_timeout_msecs *= 1000;
		} else if (strcmp(key, "proxy_refresh") == 0) {
			if (str_to_uint(value, &reply_r->proxy_refresh_secs) < 0) {
				i_error("BUG: Auth service returned invalid "
					"proxy_refresh value: %s", value);
			}
		} else if (strcmp(key, "proxy_mech") == 0)
			reply_r->proxy_mech = value;
		else if (strcmp(key, "proxy_nopipelining") == 0)
			reply_r->proxy_nopipelining = TRUE;
		else if (strcmp(key, "proxy_not_trusted") == 0)
			reply_r->proxy_not_trusted = TRUE;
		else if (strcmp(key, "master") == 0)
			reply_r->master_user = value;
		else if (strcmp(key, "ssl") == 0) {
			reply_r->ssl_flags |= PROXY_SSL_FLAG_YES;
			if (strcmp(value, "any-cert") == 0)
				reply_r->ssl_flags |= PROXY_SSL_FLAG_ANY_CERT;
			if (reply_r->port == 0)
				reply_r->port = login_binary->default_ssl_port;
		} else if (strcmp(key, "starttls") == 0) {
			reply_r->ssl_flags |= PROXY_SSL_FLAG_YES |
				PROXY_SSL_FLAG_STARTTLS;
			if (strcmp(value, "any-cert") == 0)
				reply_r->ssl_flags |= PROXY_SSL_FLAG_ANY_CERT;
		} else if (strcmp(key, "user") == 0 ||
			   strcmp(key, "postlogin_socket") == 0) {
			/* already handled in sasl-server.c */
		} else if (strncmp(key, "user_", 5) == 0) {
			if (success) {
				alt_username_set(&alt_usernames, client->pool,
						 key, value);
			}
		} else if (strncmp(key, "forward_", 8) == 0) {
			/* these are passed to upstream */
		} else if (client->set->auth_debug)
			i_debug("Ignoring unknown passdb extra field: %s", key);
	}
	if (array_count(&alt_usernames) > 0) {
		const char **alt;

		alt = p_new(client->pool, const char *,
			    array_count(&alt_usernames) + 1);
		memcpy(alt, array_idx(&alt_usernames, 0),
		       sizeof(*alt) * array_count(&alt_usernames));
		client->alt_usernames = alt;
	}
	if (reply_r->port == 0)
		reply_r->port = login_binary->default_port;

	if (reply_r->destuser == NULL)
		reply_r->destuser = client->virtual_user;
}

static void proxy_free_password(struct client *client)
{
	if (client->proxy_password == NULL)
		return;

	safe_memset(client->proxy_password, 0, strlen(client->proxy_password));
	i_free_and_null(client->proxy_password);
}

void client_proxy_finish_destroy_client(struct client *client)
{
	string_t *str = t_str_new(128);

	if (client->input->closed) {
		/* input stream got closed in client_send_raw_data().
		   In most places we don't have to check for this explicitly,
		   but login_proxy_detach() attempts to get and use the
		   istream's fd, which is now -1. */
		client_destroy(client, "Disconnected");
		return;
	}

	str_printfa(str, "proxy(%s): started proxying to %s:%u",
		    client->virtual_user,
		    login_proxy_get_host(client->login_proxy),
		    login_proxy_get_port(client->login_proxy));
	if (strcmp(client->virtual_user, client->proxy_user) != 0) {
		/* remote username is different, log it */
		str_append_c(str, '/');
		str_append(str, client->proxy_user);
	}
	if (client->proxy_master_user != NULL)
		str_printfa(str, " (master %s)", client->proxy_master_user);

	login_proxy_detach(client->login_proxy);
	client_destroy_success(client, str_c(str));
}

static void client_proxy_error(struct client *client, const char *text)
{
	client->v.proxy_error(client, text);
}

const char *client_proxy_get_state(struct client *client)
{
	return client->v.proxy_get_state(client);
}

void client_proxy_log_failure(struct client *client, const char *line)
{
	string_t *str = t_str_new(128);

	str_printfa(str, "proxy(%s): Login failed to %s:%u",
		    client->virtual_user,
		    login_proxy_get_host(client->login_proxy),
		    login_proxy_get_port(client->login_proxy));
	if (strcmp(client->virtual_user, client->proxy_user) != 0) {
		/* remote username is different, log it */
		str_append_c(str, '/');
		str_append(str, client->proxy_user);
	}
	if (client->proxy_master_user != NULL)
		str_printfa(str, " (master %s)", client->proxy_master_user);
	str_append(str, ": ");
	str_append(str, line);
	client_log(client, str_c(str));
}

void client_proxy_failed(struct client *client, bool send_line)
{
	if (send_line) {
		client_proxy_error(client, PROXY_FAILURE_MSG);
	}

	if (client->proxy_sasl_client != NULL)
		dsasl_client_free(&client->proxy_sasl_client);
	login_proxy_free(&client->login_proxy);
	proxy_free_password(client);
	i_free_and_null(client->proxy_user);
	i_free_and_null(client->proxy_master_user);

	/* call this last - it may destroy the client */
	client_auth_failed(client);
}

static void proxy_input(struct client *client)
{
	struct istream *input;
	struct ostream *output;
	const char *line;
	unsigned int duration;

	if (client->login_proxy == NULL) {
		/* we're just freeing the proxy */
		return;
	}

	input = login_proxy_get_istream(client->login_proxy);
	if (input == NULL) {
		if (client->destroyed) {
			/* we came here from client_destroy() */
			return;
		}

		/* failed for some reason, probably server disconnected */
		client_proxy_failed(client, TRUE);
		return;
	}

	i_assert(!client->destroyed);

	switch (i_stream_read(input)) {
	case -2:
		client_log_err(client, "proxy: Remote input buffer full");
		client_proxy_failed(client, TRUE);
		return;
	case -1:
		line = i_stream_next_line(input);
		duration = ioloop_time - client->created;
		client_log_err(client, t_strdup_printf(
			"proxy: Remote %s:%u disconnected: %s "
			"(state=%s, duration=%us)%s",
			login_proxy_get_host(client->login_proxy),
			login_proxy_get_port(client->login_proxy),
			io_stream_get_disconnect_reason(input, NULL),
			client_proxy_get_state(client), duration,
			line == NULL ? "" : t_strdup_printf(
				" - BUG: line not read: %s", line)));
		client_proxy_failed(client, TRUE);
		return;
	}

	output = client->output;
	o_stream_ref(output);
	o_stream_cork(output);
	while ((line = i_stream_next_line(input)) != NULL) {
		if (client->v.proxy_parse_line(client, line) != 0)
			break;
	}
	o_stream_uncork(output);
	o_stream_unref(&output);
}

static int proxy_start(struct client *client,
		       const struct client_auth_reply *reply)
{
	struct login_proxy_settings proxy_set;
	const struct dsasl_client_mech *sasl_mech = NULL;

	i_assert(reply->destuser != NULL);
	i_assert(!client->destroyed);
	i_assert(client->proxy_sasl_client == NULL);

	client->proxy_mech = NULL;
	client->v.proxy_reset(client);

	if (reply->password == NULL) {
		client_log_err(client, "proxy: password not given");
		client_proxy_error(client, PROXY_FAILURE_MSG);
		return -1;
	}
	if (reply->host == NULL || *reply->host == '\0') {
		client_log_err(client, "proxy: host not given");
		client_proxy_error(client, PROXY_FAILURE_MSG);
		return -1;
	}

	if (reply->proxy_mech != NULL) {
		sasl_mech = dsasl_client_mech_find(reply->proxy_mech);
		if (sasl_mech == NULL) {
			client_log_err(client, t_strdup_printf(
				"proxy: Unsupported SASL mechanism %s",
				reply->proxy_mech));
			client_proxy_error(client, PROXY_FAILURE_MSG);
			return -1;
		}
	} else if (reply->master_user != NULL) {
		/* have to use PLAIN authentication with master user logins */
		sasl_mech = &dsasl_client_mech_plain;
	}

	i_assert(client->refcount > 1);

	if (client->destroyed) {
		/* connection_queue_add() decided that we were the oldest
		   connection and killed us. */
		return -1;
	}
	if (login_proxy_is_ourself(client, reply->host, reply->port,
				   reply->destuser)) {
		client_log_err(client, "Proxying loops to itself");
		client_proxy_error(client, PROXY_FAILURE_MSG);
		return -1;
	}

	i_zero(&proxy_set);
	proxy_set.host = reply->host;
	if (reply->hostip != NULL &&
	    net_addr2ip(reply->hostip, &proxy_set.ip) < 0)
		proxy_set.ip.family = 0;
	if (reply->source_ip != NULL) {
		if (net_addr2ip(reply->source_ip, &proxy_set.source_ip) < 0)
			proxy_set.source_ip.family = 0;
	} else if (login_source_ips_count > 0) {
		/* select the next source IP with round robin. */
		proxy_set.source_ip = login_source_ips[login_source_ips_idx];
		login_source_ips_idx =
			(login_source_ips_idx + 1) % login_source_ips_count;
	}
	proxy_set.port = reply->port;
	proxy_set.connect_timeout_msecs = reply->proxy_timeout_msecs;
	if (proxy_set.connect_timeout_msecs == 0)
		proxy_set.connect_timeout_msecs = PROXY_DEFAULT_TIMEOUT_MSECS;
	proxy_set.notify_refresh_secs = reply->proxy_refresh_secs;
	proxy_set.ssl_flags = reply->ssl_flags;

	if (login_proxy_new(client, &proxy_set, proxy_input) < 0) {
		client_proxy_error(client, PROXY_FAILURE_MSG);
		return -1;
	}

	client->proxy_mech = sasl_mech;
	client->proxy_user = i_strdup(reply->destuser);
	client->proxy_master_user = i_strdup(reply->master_user);
	client->proxy_password = i_strdup(reply->password);
	client->proxy_nopipelining = reply->proxy_nopipelining;
	client->proxy_not_trusted = reply->proxy_not_trusted;

	/* disable input until authentication is finished */
	if (client->io != NULL)
		io_remove(&client->io);
	return 0;
}

static void ATTR_NULL(3, 4)
client_auth_result(struct client *client, enum client_auth_result result,
		   const struct client_auth_reply *reply, const char *text)
{
	o_stream_cork(client->output);
	client->v.auth_result(client, result, reply, text);
	o_stream_uncork(client->output);
}

static bool
client_auth_handle_reply(struct client *client,
			 const struct client_auth_reply *reply, bool success)
{
	if (reply->proxy) {
		/* we want to proxy the connection to another server.
		   don't do this unless authentication succeeded. with
		   master user proxying we can get FAIL with proxy still set.

		   proxy host=.. [port=..] [destuser=..] pass=.. */
		if (!success)
			return FALSE;
		if (proxy_start(client, reply) < 0)
			client_auth_failed(client);
		else {
			/* this for plugins being able th hook into auth reply
			   when proxying is used */
			client_auth_result(client, CLIENT_AUTH_RESULT_SUCCESS,
					   reply, NULL);
		}
		return TRUE;
	}

	if (reply->host != NULL) {
		const char *reason;

		if (reply->reason != NULL)
			reason = reply->reason;
		else if (reply->nologin)
			reason = "Try this server instead.";
		else
			reason = "Logged in, but you should use this server instead.";

		if (reply->nologin) {
			client_auth_result(client,
				CLIENT_AUTH_RESULT_REFERRAL_NOLOGIN,
				reply, reason);
		} else {
			client_auth_result(client,
				CLIENT_AUTH_RESULT_REFERRAL_SUCCESS,
				reply, reason);
			return TRUE;
		}
	} else if (reply->nologin) {
		/* Authentication went ok, but for some reason user isn't
		   allowed to log in. Shouldn't probably happen. */
		if (reply->reason != NULL) {
			client_auth_result(client,
				CLIENT_AUTH_RESULT_AUTHFAILED_REASON,
				reply, reply->reason);
		} else if (reply->temp) {
			const char *timestamp, *msg;

			timestamp = t_strflocaltime("%Y-%m-%d %H:%M:%S", ioloop_time);
			msg = t_strdup_printf(AUTH_TEMP_FAILED_MSG" [%s:%s]",
				      my_hostname, timestamp);
			client_auth_result(client, CLIENT_AUTH_RESULT_TEMPFAIL,
					   reply, msg);
		} else if (reply->authz_failure) {
			client_auth_result(client,
				CLIENT_AUTH_RESULT_AUTHZFAILED, reply,
				"Authorization failed");
		} else {
			client_auth_result(client,
				CLIENT_AUTH_RESULT_AUTHFAILED, reply,
				AUTH_FAILED_MSG);
		}
	} else {
		/* normal login/failure */
		return FALSE;
	}

	i_assert(reply->nologin);

	if (!client->destroyed)
		client_auth_failed(client);
	return TRUE;
}

void client_auth_respond(struct client *client, const char *response)
{
	client->auth_waiting = FALSE;
	client_set_auth_waiting(client);
	auth_client_request_continue(client->auth_request, response);
	io_remove(&client->io);
}

void client_auth_abort(struct client *client)
{
	sasl_server_auth_abort(client);
}

void client_auth_fail(struct client *client, const char *text)
{
	sasl_server_auth_failed(client, text);
}

int client_auth_read_line(struct client *client)
{
	const unsigned char *data;
	size_t i, size, len;

	if (i_stream_read_data(client->input, &data, &size, 0) == -1) {
		client_destroy(client, "Disconnected");
		return -1;
	}

	/* see if we have a full line */
	for (i = 0; i < size; i++) {
		if (data[i] == '\n')
			break;
	}
	if (client->auth_response == NULL)
		client->auth_response = str_new(default_pool, I_MAX(i+1, 256));
	if (str_len(client->auth_response) + i > LOGIN_MAX_AUTH_BUF_SIZE) {
		client_destroy(client, "Authentication response too large");
		return -1;
	}
	str_append_n(client->auth_response, data, i);
	i_stream_skip(client->input, i == size ? size : i+1);

	/* drop trailing \r */
	len = str_len(client->auth_response);
	if (len > 0 && str_c(client->auth_response)[len-1] == '\r')
		str_truncate(client->auth_response, len-1);

	return i < size;
}

void client_auth_parse_response(struct client *client)
{
	if (client_auth_read_line(client) <= 0)
		return;

	if (strcmp(str_c(client->auth_response), "*") == 0) {
		sasl_server_auth_abort(client);
		return;
	}

	client_auth_respond(client, str_c(client->auth_response));
	memset(str_c_modifiable(client->auth_response), 0,
	       str_len(client->auth_response));
}

static void client_auth_input(struct client *client)
{
	i_assert(client->v.auth_parse_response != NULL);
	client->v.auth_parse_response(client);
}

void client_auth_send_challenge(struct client *client, const char *data)
{
	struct const_iovec iov[3];

	iov[0].iov_base = "+ ";
	iov[0].iov_len = 2;
	iov[1].iov_base = data;
	iov[1].iov_len = strlen(data);
	iov[2].iov_base = "\r\n";
	iov[2].iov_len = 2;

	o_stream_nsendv(client->output, iov, 3);
}

static void
sasl_callback(struct client *client, enum sasl_server_reply sasl_reply,
	      const char *data, const char *const *args)
{
	struct client_auth_reply reply;

	i_assert(!client->destroyed ||
		 sasl_reply == SASL_SERVER_REPLY_AUTH_ABORTED ||
		 sasl_reply == SASL_SERVER_REPLY_MASTER_FAILED);

	i_zero(&reply);
	switch (sasl_reply) {
	case SASL_SERVER_REPLY_SUCCESS:
		if (client->to_auth_waiting != NULL)
			timeout_remove(&client->to_auth_waiting);
		if (args != NULL) {
			client_auth_parse_args(client, TRUE, args, &reply);
			reply.all_fields = args;
			if (client_auth_handle_reply(client, &reply, TRUE))
				break;
		}
		client_auth_result(client, CLIENT_AUTH_RESULT_SUCCESS,
				   &reply, NULL);
		client_destroy_success(client, "Login");
		break;
	case SASL_SERVER_REPLY_AUTH_FAILED:
	case SASL_SERVER_REPLY_AUTH_ABORTED:
		if (client->to_auth_waiting != NULL)
			timeout_remove(&client->to_auth_waiting);
		if (args != NULL) {
			client_auth_parse_args(client, FALSE, args, &reply);
			reply.nologin = TRUE;
			reply.all_fields = args;
			if (client_auth_handle_reply(client, &reply, FALSE))
				break;
		}

		if (sasl_reply == SASL_SERVER_REPLY_AUTH_ABORTED) {
			client_auth_result(client, CLIENT_AUTH_RESULT_ABORTED,
				&reply, "Authentication aborted by client.");
		} else if (data == NULL) {
			client_auth_result(client,
				CLIENT_AUTH_RESULT_AUTHFAILED, &reply,
				AUTH_FAILED_MSG);
		} else {
			client_auth_result(client,
				CLIENT_AUTH_RESULT_AUTHFAILED_REASON, &reply,
				data);
		}

		if (!client->destroyed)
			client_auth_failed(client);
		break;
	case SASL_SERVER_REPLY_MASTER_FAILED:
		if (data != NULL) {
			/* authentication itself succeeded, we just hit some
			   internal failure. */
			client_auth_result(client, CLIENT_AUTH_RESULT_TEMPFAIL,
					   &reply, data);
		}

		/* the fd may still be hanging somewhere in kernel or another
		   process. make sure the client gets disconnected. */
		if (shutdown(client->fd, SHUT_RDWR) < 0 && errno != ENOTCONN)
			i_error("shutdown() failed: %m");

		if (data == NULL)
			client_destroy_internal_failure(client);
		else
			client_destroy_success(client, data);
		break;
	case SASL_SERVER_REPLY_CONTINUE:
		i_assert(client->v.auth_send_challenge != NULL);
		client->v.auth_send_challenge(client, data);

		if (client->to_auth_waiting != NULL)
			timeout_remove(&client->to_auth_waiting);

		if (client->auth_response != NULL)
			str_truncate(client->auth_response, 0);

		i_assert(client->io == NULL);
		client->auth_waiting = TRUE;
		client->io = io_add(client->fd, IO_READ,
				    client_auth_input, client);
		client_auth_input(client);
		return;
	}

	client_unref(&client);
}

int client_auth_begin(struct client *client, const char *mech_name,
		      const char *init_resp)
{
	if (!client->secured && strcmp(client->ssl_set->ssl, "required") == 0) {
		if (client->set->auth_verbose) {
			client_log(client, "Login failed: "
				   "SSL required for authentication");
		}
		client->auth_attempts++;
		client_auth_result(client, CLIENT_AUTH_RESULT_SSL_REQUIRED, NULL,
			"Authentication not allowed until SSL/TLS is enabled.");
		return 1;
	}


	client_ref(client);
	client->auth_initializing = TRUE;
	sasl_server_auth_begin(client, login_binary->protocol, mech_name,
			       init_resp, sasl_callback);
	client->auth_initializing = FALSE;
	if (!client->authenticating)
		return 1;

	/* don't handle input until we get the initial auth reply */
	if (client->io != NULL)
		io_remove(&client->io);
	client_set_auth_waiting(client);
	return 0;
}

bool client_check_plaintext_auth(struct client *client, bool pass_sent)
{
	if (client->secured || (!client->set->disable_plaintext_auth &&
				strcmp(client->ssl_set->ssl, "required") != 0))
		return TRUE;

	if (client->set->auth_verbose) {
		client_log(client, "Login failed: "
			   "Plaintext authentication disabled");
	}
	if (pass_sent) {
		client_notify_status(client, TRUE,
			 "Plaintext authentication not allowed "
			 "without SSL/TLS, but your client did it anyway. "
			 "If anyone was listening, the password was exposed.");
	}
	client_auth_result(client, CLIENT_AUTH_RESULT_SSL_REQUIRED, NULL,
			   AUTH_PLAINTEXT_DISABLED_MSG);
	client->auth_tried_disabled_plaintext = TRUE;
	client->auth_attempts++;
	return FALSE;
}

void clients_notify_auth_connected(void)
{
	struct client *client, *next;

	for (client = clients; client != NULL; client = next) {
		next = client->next;

		if (client->to_auth_waiting != NULL)
			timeout_remove(&client->to_auth_waiting);

		client_notify_auth_ready(client);

		if (client->input_blocked) {
			client->input_blocked = FALSE;
			client_input(client);
		}
	}
}
