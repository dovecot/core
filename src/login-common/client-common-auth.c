/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "hostpid.h"
#include "login-common.h"
#include "array.h"
#include "iostream.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "strescape.h"
#include "safe-memset.h"
#include "time-util.h"
#include "settings-parser.h"
#include "login-proxy.h"
#include "auth-client.h"
#include "dsasl-client.h"
#include "master-service-ssl-settings.h"
#include "client-common.h"

/* If we've been waiting auth server to respond for over this many milliseconds,
   send a "waiting" message. */
#define AUTH_WAITING_TIMEOUT_MSECS (30*1000)
#define AUTH_WAITING_WARNING_TIMEOUT_MSECS (10*1000)

struct client_auth_fail_code_id {
	const char *id;
	enum client_auth_fail_code code;
};

static const struct client_auth_fail_code_id client_auth_fail_codes[] = {
	{ AUTH_CLIENT_FAIL_CODE_AUTHZFAILED,
		CLIENT_AUTH_FAIL_CODE_AUTHZFAILED },
	{ AUTH_CLIENT_FAIL_CODE_TEMPFAIL,
		CLIENT_AUTH_FAIL_CODE_TEMPFAIL },
	{ AUTH_CLIENT_FAIL_CODE_USER_DISABLED,
		CLIENT_AUTH_FAIL_CODE_USER_DISABLED },
	{ AUTH_CLIENT_FAIL_CODE_PASS_EXPIRED,
		CLIENT_AUTH_FAIL_CODE_PASS_EXPIRED },
	{ AUTH_CLIENT_FAIL_CODE_INVALID_BASE64,
		CLIENT_AUTH_FAIL_CODE_INVALID_BASE64 },
	{ AUTH_CLIENT_FAIL_CODE_MECH_INVALID,
		CLIENT_AUTH_FAIL_CODE_MECH_INVALID },
	{ AUTH_CLIENT_FAIL_CODE_MECH_SSL_REQUIRED,
		CLIENT_AUTH_FAIL_CODE_MECH_SSL_REQUIRED },
	{ AUTH_CLIENT_FAIL_CODE_ANONYMOUS_DENIED,
		CLIENT_AUTH_FAIL_CODE_ANONYMOUS_DENIED },
	{ NULL, CLIENT_AUTH_FAIL_CODE_NONE }
};

static enum client_auth_fail_code
client_auth_fail_code_lookup(const char *fail_code)
{
	const struct client_auth_fail_code_id *fail = client_auth_fail_codes;

	while (fail->id != NULL) {
		if (strcmp(fail->id, fail_code) == 0)
			return fail->code;
		fail++;
	}

	return CLIENT_AUTH_FAIL_CODE_NONE;
}

static void client_auth_failed(struct client *client)
{
	i_free_and_null(client->master_data_prefix);
	if (client->auth_response != NULL)
		str_truncate(client->auth_response, 0);

	if (client->auth_initializing || client->destroyed)
		return;

	io_remove(&client->io);

	if (!client_does_custom_io(client)) {
		client->io = io_add_istream(client->input, client_input, client);
		io_set_pending(client->io);
	}
}

static void client_auth_waiting_timeout(struct client *client)
{
	if (!client->notified_auth_ready) {
		e_warning(client->event, "Auth process not responding, "
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
		array_push_back(&global_alt_usernames, &new_key);
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
		array_push_back(alt_usernames, &empty_str);
	}
	array_push_back(alt_usernames, &value);
}

static bool client_auth_parse_args(const struct client *client, bool success,
				   const char *const *args,
				   struct client_auth_reply *reply_r)
{
	const char *key, *value, *p, *error;
	int ret;

	i_zero(reply_r);
	t_array_init(&reply_r->alt_usernames, 4);
	reply_r->proxy_host_immediate_failure_after_secs =
		LOGIN_PROXY_DEFAULT_HOST_IMMEDIATE_FAILURE_AFTER_SECS;

	for (; *args != NULL; args++) {
		p = strchr(*args, '=');
		if (p == NULL) {
			key = *args;
			value = "";
		} else {
			key = t_strdup_until(*args, p);
			value = p + 1;
		}
		ret = auth_proxy_settings_parse(&reply_r->proxy, NULL,
						key, value, &error);
		if (ret < 0) {
			e_error(client->event, "Auth service returned invalid "
				"%s value '%s': %s", key, value, error);
			return FALSE;
		}
		if (ret > 0)
			continue;

		if (strcmp(key, "nologin") == 0) {
			reply_r->nologin = TRUE;
			reply_r->fail_code = CLIENT_AUTH_FAIL_CODE_LOGIN_DISABLED;
		} else if (strcmp(key, "reason") == 0)
			reply_r->reason = value;
		else if (strcmp(key, "proxy_host_immediate_failure_after") == 0) {
			if (settings_get_time(value,
				&reply_r->proxy_host_immediate_failure_after_secs,
				&error) < 0) {
				e_error(client->event,
					"Auth service returned invalid "
					"proxy_host_immediate_failure_after value '%s': %s",
					value, error);
				return FALSE;
			}
		} else if (strcmp(key, "proxy_refresh") == 0) {
			if (str_to_uint(value, &reply_r->proxy_refresh_secs) < 0) {
				e_error(client->event,
					"Auth service returned invalid "
					"proxy_refresh value: %s", value);
				return FALSE;
			}
		} else if (strcmp(key, "code") == 0) {
			if (reply_r->fail_code != CLIENT_AUTH_FAIL_CODE_NONE) {
				/* code already assigned */
			} else {
				reply_r->fail_code = client_auth_fail_code_lookup(value);
			}
		} else if (strcmp(key, "user") == 0 ||
			   strcmp(key, "postlogin_socket") == 0) {
			/* already handled in sasl-server.c */
		} else if (str_begins_with(key, "user_")) {
			if (success) {
				alt_username_set(&reply_r->alt_usernames,
						 client->pool, key, value);
			}
		} else if (str_begins_with(key, "forward_")) {
			/* these are passed to upstream */
		} else
			e_debug(event_auth, "Ignoring unknown passdb extra field: %s", key);
	}
	if (reply_r->proxy.port == 0) {
		if ((reply_r->proxy.ssl_flags & AUTH_PROXY_SSL_FLAG_YES) != 0 &&
		    (reply_r->proxy.ssl_flags & AUTH_PROXY_SSL_FLAG_STARTTLS) == 0)
			reply_r->proxy.port = login_binary->default_ssl_port;
		else
			reply_r->proxy.port = login_binary->default_port;
	}

	if (reply_r->proxy.username == NULL)
		reply_r->proxy.username = client->virtual_user;

	if (reply_r->proxy.proxy) {
		if (reply_r->proxy.password == NULL) {
			e_error(client->event, "proxy: pass field is missing");
			return FALSE;
		}
		if (reply_r->proxy.host == NULL ||
		    reply_r->proxy.host[0] == '\0') {
			e_error(client->event, "proxy: host field not given");
			return FALSE;
		}

		if (reply_r->proxy.host_ip.family == 0 &&
		    net_addr2ip(reply_r->proxy.host,
				&reply_r->proxy.host_ip) < 0) {
			e_error(client->event,
				"proxy: host %s is not an IP (auth should have changed it)",
				reply_r->proxy.host);
			return FALSE;
		}
	}
	return TRUE;
}

static void proxy_free_password(struct client *client)
{
	if (client->proxy_password == NULL)
		return;

	safe_memset(client->proxy_password, 0, strlen(client->proxy_password));
	i_free_and_null(client->proxy_password);
}

static void client_proxy_append_conn_info(string_t *str, struct client *client)
{
	const char *source_host;

	source_host = login_proxy_get_source_host(client->login_proxy);
	if (source_host[0] != '\0')
		str_printfa(str, " from %s", source_host);
	if (strcmp(client->virtual_user, client->proxy_user) != 0) {
		/* remote username is different, log it */
		str_printfa(str, " as user %s", client->proxy_user);
	}
	if (client->proxy_master_user != NULL)
		str_printfa(str, " (master %s)", client->proxy_master_user);
}

void client_proxy_finish_destroy_client(struct client *client)
{
	string_t *str = t_str_new(128);

	if (client->input->closed) {
		/* input stream got closed in client_send_raw_data().
		   In most places we don't have to check for this explicitly,
		   but login_proxy_detach() attempts to get and use the
		   istream's fd, which is now -1. */
		client_destroy_iostream_error(client);
		return;
	}

	/* Include hostname in the log message in case it's different from the
	   IP address in the prefix. */
	const char *ip_str = login_proxy_get_ip_str(client->login_proxy);
	const char *host = login_proxy_get_host(client->login_proxy);
	str_printfa(str, "Started proxying to <%s>",
		    login_proxy_get_ip_str(client->login_proxy));
	if (strcmp(ip_str, host) != 0)
		str_printfa(str, " (<%s>)", host);

	client_proxy_append_conn_info(str, client);

	struct event *proxy_event = login_proxy_get_event(client->login_proxy);
	login_proxy_append_success_log_info(client->login_proxy, str);
	struct event_passthrough *e = event_create_passthrough(proxy_event)->
		set_name("proxy_session_established");
	e_info(e->event(), "%s", str_c(str));
	login_proxy_detach(client->login_proxy);
	client_destroy_success(client, NULL);
}

const char *client_proxy_get_state(struct client *client)
{
	return client->v.proxy_get_state(client);
}

void client_proxy_log_failure(struct client *client, const char *line)
{
	string_t *str = t_str_new(128);

	str_printfa(str, "Login failed");
	client_proxy_append_conn_info(str, client);
	str_append(str, ": ");
	str_append(str, line);
	e_info(login_proxy_get_event(client->login_proxy), "%s", str_c(str));
}

static void client_proxy_failed(struct client *client)
{
	login_proxy_free(&client->login_proxy);
	proxy_free_password(client);
	i_free_and_null(client->proxy_user);
	i_free_and_null(client->proxy_master_user);

	client_auth_failed(client);
}

static void proxy_input(struct client *client)
{
	struct istream *input;
	struct ostream *output;
	const char *line;
	unsigned int duration;

	input = login_proxy_get_istream(client->login_proxy);
	switch (i_stream_read(input)) {
	case -2:
		login_proxy_failed(client->login_proxy,
				   login_proxy_get_event(client->login_proxy),
				   LOGIN_PROXY_FAILURE_TYPE_PROTOCOL,
				   "Too long input line");
		return;
	case -1:
		line = i_stream_next_line(input);
		duration = ioloop_time - client->created.tv_sec;
		const char *reason = t_strdup_printf(
			"Disconnected by server: %s "
			"(state=%s, duration=%us)%s",
			io_stream_get_disconnect_reason(input, NULL),
			client_proxy_get_state(client), duration,
			line == NULL ? "" : t_strdup_printf(
				" - BUG: line not read: %s", line));
		login_proxy_failed(client->login_proxy,
				   login_proxy_get_event(client->login_proxy),
				   LOGIN_PROXY_FAILURE_TYPE_CONNECT, reason);
		return;
	}

	output = client->output;
	/* The "line" variable is allocated from the istream, but the istream
	   may be freed by proxy_parse_line(). Keep the istream referenced to
	   make sure the line isn't freed too early. */
	i_stream_ref(input);
	o_stream_ref(output);
	o_stream_cork(output);
	while ((line = i_stream_next_line(input)) != NULL) {
		if (client->v.proxy_parse_line(client, line) != 0)
			break;
	}
	o_stream_uncork(output);
	o_stream_unref(&output);
	i_stream_unref(&input);
}

static void proxy_reset(struct client *client)
{
	dsasl_client_free(&client->proxy_sasl_client);
	client->v.proxy_reset(client);
}

static void
proxy_redirect_reauth_callback(struct auth_client_request *request,
			       enum auth_request_status status,
			       const char *data_base64 ATTR_UNUSED,
			       const char *const *args, void *context)
{
	struct client *client = context;
	struct client_auth_reply reply;
	const char *error = NULL;

	i_assert(client->reauth_request == request);

	client->reauth_request = NULL;
	switch (status) {
	case AUTH_REQUEST_STATUS_CONTINUE:
		error = "Unexpected SASL continuation request received";
		break;
	case AUTH_REQUEST_STATUS_OK:
		if (!client_auth_parse_args(client, FALSE, args, &reply)) {
			error = "Redirect authentication returned invalid input";
			break;
		}

		if (!reply.proxy.proxy) {
			error = "Redirect authentication is missing proxy field";
			break;
		}
		login_proxy_redirect_finish(client->login_proxy,
					    &reply.proxy.host_ip,
					    reply.proxy.port);
		return;
	case AUTH_REQUEST_STATUS_INTERNAL_FAIL:
		error = "Internal authentication failure";
		break;
	case AUTH_REQUEST_STATUS_FAIL:
		if (!client_auth_parse_args(client, FALSE, args, &reply))
			error = "Failed to parse auth reply";
		else if (reply.reason == NULL || reply.reason[0] == '\0')
			error = "Redirect authentication unexpectedly failed";
		else
			error = t_strdup_printf(
				"Redirect authentication unexpectedly failed: %s",
				reply.reason);
		break;
	case AUTH_REQUEST_STATUS_ABORT:
		error = "Redirect authentication aborted";
		break;
	}
	i_assert(error != NULL);
	login_proxy_failed(client->login_proxy,
			   login_proxy_get_event(client->login_proxy),
			   LOGIN_PROXY_FAILURE_TYPE_INTERNAL, error);
}

static void
proxy_redirect_reauth(struct client *client, const char *destuser,
		      const struct ip_addr *ip, in_port_t port)
{
	struct auth_request_info info;
	const char *client_error;

	if (sasl_server_auth_request_info_fill(client, &info, &client_error) < 0) {
		const char *error = t_strdup_printf(
			"Unexpected failure on reauth: %s", client_error);
		login_proxy_failed(client->login_proxy,
			login_proxy_get_event(client->login_proxy),
			LOGIN_PROXY_FAILURE_TYPE_INTERNAL, error);
		return;
	}
	string_t *hosts_attempted = t_str_new(64);
	str_append(hosts_attempted, "proxy_redirect_host_attempts=");
	login_proxy_get_redirect_path(client->login_proxy, hosts_attempted);
	unsigned int connect_timeout_msecs =
		login_proxy_get_connect_timeout_msecs(client->login_proxy);
	const char *const extra_fields[] = {
		t_strdup_printf("proxy_redirect_host_next=%s",
				net_ipport2str(ip, port)),
		str_c(hosts_attempted),
		t_strdup_printf("destuser=%s", str_tabescape(destuser)),
		t_strdup_printf("proxy_timeout=%u", connect_timeout_msecs),
	};
	info.mech = "EXTERNAL";
	t_array_init(&info.extra_fields, N_ELEMENTS(extra_fields));
	array_append(&info.extra_fields, extra_fields,
		     N_ELEMENTS(extra_fields));
	client->reauth_request =
		auth_client_request_new(auth_client, &info,
					proxy_redirect_reauth_callback, client);
}

static bool
proxy_try_redirect(struct client *client, const char *destination,
		   const char **error_r)
{
	const char *host, *p, *destuser = client->proxy_user;
	struct ip_addr ip;
	in_port_t port;

	p = strrchr(destination, '@');
	if (p != NULL) {
		destuser = t_strdup_until(destination, p);
		destination = p+1;
	}
	if (net_str2hostport(destination,
			     login_proxy_get_port(client->login_proxy),
			     &host, &port) < 0) {
		*error_r = t_strdup_printf(
			"Failed to parse host:port '%s'", destination);
		return FALSE;
	}
	if (net_addr2ip(host, &ip) < 0) {
		*error_r = t_strdup_printf(
			"Failed to parse IP '%s' (DNS lookups not supported)",
			host);
		return FALSE;
	}
	/* At least for now we support sending the destuser only for reauth
	   requests. */
	if (client->proxy_redirect_reauth)
		proxy_redirect_reauth(client, destuser, &ip, port);
	else
		login_proxy_redirect_finish(client->login_proxy, &ip, port);
	return TRUE;
}

static void
proxy_redirect(struct client *client, struct event *event,
	       const char *destination)
{
	const char *error;

	proxy_reset(client);
	if (!proxy_try_redirect(client, destination, &error)) {
		login_proxy_failed(client->login_proxy, event,
			LOGIN_PROXY_FAILURE_TYPE_INTERNAL_CONFIG,
			t_strdup_printf("Redirect to %s: %s", destination, error));
	}
}

void client_common_proxy_failed(struct client *client,
				enum login_proxy_failure_type type,
				const char *reason ATTR_UNUSED,
				bool reconnecting)
{
	proxy_reset(client);
	if (reconnecting)
		return;

	switch (type) {
	case LOGIN_PROXY_FAILURE_TYPE_CONNECT:
	case LOGIN_PROXY_FAILURE_TYPE_INTERNAL:
	case LOGIN_PROXY_FAILURE_TYPE_INTERNAL_CONFIG:
	case LOGIN_PROXY_FAILURE_TYPE_REMOTE:
	case LOGIN_PROXY_FAILURE_TYPE_REMOTE_CONFIG:
	case LOGIN_PROXY_FAILURE_TYPE_PROTOCOL:
		break;
	case LOGIN_PROXY_FAILURE_TYPE_AUTH:
	case LOGIN_PROXY_FAILURE_TYPE_AUTH_TEMPFAIL:
	case LOGIN_PROXY_FAILURE_TYPE_AUTH_REDIRECT:
		client->proxy_auth_failed = TRUE;
		break;
	}
	client_proxy_failed(client);
}

static bool
proxy_check_start(struct client *client, struct event *event,
		  const struct client_auth_reply *reply,
		  const struct dsasl_client_mech **sasl_mech_r)
{
	i_assert(reply->proxy.password != NULL);
	i_assert(reply->proxy.host != NULL && reply->proxy.host[0] != '\0');
	i_assert(reply->proxy.host_ip.family != 0);

	if (reply->proxy.sasl_mechanism != NULL) {
		*sasl_mech_r = dsasl_client_mech_find(reply->proxy.sasl_mechanism);
		if (*sasl_mech_r == NULL) {
			e_error(event, "Unsupported SASL mechanism %s",
				reply->proxy.sasl_mechanism);
			return FALSE;
		}
	} else if (reply->proxy.master_user != NULL) {
		/* have to use PLAIN authentication with master user logins */
		*sasl_mech_r = &dsasl_client_mech_plain;
	}

	if (login_proxy_is_ourself(client, reply->proxy.host, reply->proxy.port,
				   reply->proxy.username)) {
		e_error(event, "Proxying loops to itself");
		return FALSE;
	}
	return TRUE;
}

static int proxy_start(struct client *client,
		       const struct client_auth_reply *reply)
{
	struct login_proxy_settings proxy_set;
	const struct dsasl_client_mech *sasl_mech = NULL;
	struct event *event;

	i_assert(reply->proxy.username != NULL);
	i_assert(client->refcount > 1);
	i_assert(!client->destroyed);
	i_assert(client->proxy_sasl_client == NULL);

	client->proxy_mech = NULL;
	client->v.proxy_reset(client);
	event = event_create(client->event);
	event_set_append_log_prefix(event, t_strdup_printf(
		"proxy(%s): ", client->virtual_user));

	if (!proxy_check_start(client, event, reply, &sasl_mech)) {
		client->v.proxy_failed(client,
			LOGIN_PROXY_FAILURE_TYPE_INTERNAL,
			LOGIN_PROXY_FAILURE_MSG, FALSE);
		event_unref(&event);
		return -1;
	}

	i_zero(&proxy_set);
	proxy_set.host = reply->proxy.host;
	proxy_set.ip = reply->proxy.host_ip;
	if (reply->proxy.source_ip.family != 0) {
		proxy_set.source_ip = reply->proxy.source_ip;
	} else if (login_source_ips_count > 0) {
		/* select the next source IP with round robin. */
		proxy_set.source_ip = login_source_ips[login_source_ips_idx];
		login_source_ips_idx =
			(login_source_ips_idx + 1) % login_source_ips_count;
	}
	proxy_set.port = reply->proxy.port;
	proxy_set.connect_timeout_msecs = reply->proxy.timeout_msecs;
	if (proxy_set.connect_timeout_msecs == 0)
		proxy_set.connect_timeout_msecs = client->set->login_proxy_timeout;
	proxy_set.notify_refresh_secs = reply->proxy_refresh_secs;
	proxy_set.ssl_flags = reply->proxy.ssl_flags;
	proxy_set.host_immediate_failure_after_secs =
		reply->proxy_host_immediate_failure_after_secs;
	proxy_set.rawlog_dir = client->set->login_proxy_rawlog_dir;

	client->proxy_mech = sasl_mech;
	client->proxy_user = i_strdup(reply->proxy.username);
	client->proxy_master_user = i_strdup(reply->proxy.master_user);
	client->proxy_password = i_strdup(reply->proxy.password);
	client->proxy_nopipelining = reply->proxy.nopipelining;
	client->proxy_noauth = reply->proxy.noauth;
	client->proxy_not_trusted = reply->proxy.remote_not_trusted;
	client->proxy_redirect_reauth = reply->proxy.redirect_reauth;

	if (login_proxy_new(client, event, &proxy_set, proxy_input,
			    client->v.proxy_failed, proxy_redirect) < 0) {
		event_unref(&event);
		return -1;
	}
	event_unref(&event);

	/* disable input until authentication is finished */
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
	if (array_count(&reply->alt_usernames) > 0) {
		const char **alt;

		alt = p_new(client->pool, const char *,
			    array_count(&reply->alt_usernames) + 1);
		memcpy(alt, array_front(&reply->alt_usernames),
		       sizeof(*alt) * array_count(&reply->alt_usernames));
		client->alt_usernames = alt;
	}

	if (reply->proxy.proxy) {
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

	if (reply->proxy.host != NULL) {
		const char *reason;

		if (reply->reason != NULL)
			reason = reply->reason;
		else if (reply->nologin)
			reason = "Try this server instead.";
		else
			reason = "Logged in, but you should use this server instead.";

		if (reply->nologin) {
			client->auth_nologin_referral = TRUE;
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
		enum client_auth_result result = CLIENT_AUTH_RESULT_AUTHFAILED;
		const char *timestamp, *reason = reply->reason;

		/* Either failed or user login is disabled */
		switch (reply->fail_code) {
		case CLIENT_AUTH_FAIL_CODE_AUTHZFAILED:
			result = CLIENT_AUTH_RESULT_AUTHZFAILED;
			if (reason == NULL)
				reason = "Authorization failed";
			break;
		case CLIENT_AUTH_FAIL_CODE_TEMPFAIL:
			result = CLIENT_AUTH_RESULT_TEMPFAIL;
			timestamp = t_strflocaltime("%Y-%m-%d %H:%M:%S", ioloop_time);
			reason = t_strdup_printf(AUTH_TEMP_FAILED_MSG" [%s:%s]",
				      my_hostname, timestamp);
			break;
		case CLIENT_AUTH_FAIL_CODE_PASS_EXPIRED:
			result = CLIENT_AUTH_RESULT_PASS_EXPIRED;
			break;
		case CLIENT_AUTH_FAIL_CODE_INVALID_BASE64:
			result = CLIENT_AUTH_RESULT_INVALID_BASE64;
			break;
		case CLIENT_AUTH_FAIL_CODE_MECH_INVALID:
			result = CLIENT_AUTH_RESULT_MECH_INVALID;
			break;
		case CLIENT_AUTH_FAIL_CODE_MECH_SSL_REQUIRED:
			result = CLIENT_AUTH_RESULT_MECH_SSL_REQUIRED;
			break;
		case CLIENT_AUTH_FAIL_CODE_ANONYMOUS_DENIED:
			result = CLIENT_AUTH_RESULT_ANONYMOUS_DENIED;
			break;
		case CLIENT_AUTH_FAIL_CODE_LOGIN_DISABLED:
			result = CLIENT_AUTH_RESULT_LOGIN_DISABLED;
			if (reason == NULL)
				reason = "Login disabled for this user";
			break;
		case CLIENT_AUTH_FAIL_CODE_USER_DISABLED:
		default:
			if (reason != NULL)
				result = CLIENT_AUTH_RESULT_AUTHFAILED_REASON;
			else
				result = CLIENT_AUTH_RESULT_AUTHFAILED;
		}

		if (reason == NULL)
			reason = AUTH_FAILED_MSG;
		client_auth_result(client, result, reply, reason);
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
	if (!client_does_custom_io(client))
		io_remove(&client->io);
}

void client_auth_abort(struct client *client)
{
	sasl_server_auth_abort(client);
}

void client_auth_fail(struct client *client, const char *text)
{
	sasl_server_auth_failed(client, text, NULL);
}

int client_auth_read_line(struct client *client)
{
	const unsigned char *data;
	size_t i, size, len;

	if (i_stream_read_more(client->input, &data, &size) == -1) {
		client_destroy_iostream_error(client);
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
	str_append_data(client->auth_response, data, i);
	i_stream_skip(client->input, i == size ? size : i+1);

	/* drop trailing \r */
	len = str_len(client->auth_response);
	if (len > 0 && str_c(client->auth_response)[len-1] == '\r')
		str_truncate(client->auth_response, len-1);

	return i < size ? 1 : 0;
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

static bool
client_auth_reply_args(struct client *client, enum sasl_server_reply sasl_reply,
		       const char *data, const char *const *args,
		       struct client_auth_reply *reply_r)
{
	bool success = sasl_reply == SASL_SERVER_REPLY_SUCCESS;

	timeout_remove(&client->to_auth_waiting);
	if (args != NULL) {
		if (!client_auth_parse_args(client, success, args, reply_r)) {
			client_auth_result(client,
				CLIENT_AUTH_RESULT_AUTHFAILED, reply_r,
				AUTH_FAILED_MSG);
			return FALSE;
		}
		if (!success) {
			if (reply_r->reason == NULL)
				reply_r->reason = data;
			reply_r->nologin = TRUE;
		}
		reply_r->all_fields = args;
		client->last_auth_fail = reply_r->fail_code;
		if (client_auth_handle_reply(client, reply_r, success))
			return FALSE;
	}
	return TRUE;
}

static void
sasl_callback(struct client *client, enum sasl_server_reply sasl_reply,
	      const char *data, const char *const *args)
{
	struct client_auth_reply reply;

	i_assert(!client->destroyed ||
		 sasl_reply == SASL_SERVER_REPLY_AUTH_ABORTED ||
		 sasl_reply == SASL_SERVER_REPLY_MASTER_FAILED);

	client->last_auth_fail = CLIENT_AUTH_FAIL_CODE_NONE;
	i_zero(&reply);
	switch (sasl_reply) {
	case SASL_SERVER_REPLY_SUCCESS:
		if (!client_auth_reply_args(client, sasl_reply,
					    data, args, &reply))
			break;

		client_auth_result(client, CLIENT_AUTH_RESULT_SUCCESS,
				   &reply, NULL);
		client_destroy_success(client, "Login");
		break;
	case SASL_SERVER_REPLY_AUTH_FAILED:
	case SASL_SERVER_REPLY_AUTH_ABORTED:
		if (!client_auth_reply_args(client, sasl_reply,
					    data, args, &reply))
			break;

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
			e_error(client->event, "shutdown() failed: %m");

		if (data != NULL) {
			/* e.g. mail_max_userip_connections is reached */
		} else {
			/* The error should have been logged already.
			   The client will only see a generic internal error. */
			client_notify_disconnect(client, CLIENT_DISCONNECT_INTERNAL_ERROR,
				"Internal login failure. "
				"Refer to server log for more information.");
			data = t_strdup_printf("Internal login failure (pid=%s id=%u)",
					       my_pid, client->master_auth_id);
		}
		client->no_extra_disconnect_reason = TRUE;
		client_destroy(client, data);
		break;
	case SASL_SERVER_REPLY_CONTINUE:
		i_assert(client->v.auth_send_challenge != NULL);
		client->v.auth_send_challenge(client, data);

		timeout_remove(&client->to_auth_waiting);

		if (client->auth_response != NULL)
			str_truncate(client->auth_response, 0);

		i_assert(client->io == NULL);
		client->auth_waiting = TRUE;
		if (!client_does_custom_io(client)) {
			client->io = io_add_istream(client->input,
						    client_auth_input, client);
			client_auth_input(client);
		}
		return;
	}

	client_unref(&client);
}

static int
client_auth_begin_common(struct client *client, const char *mech_name,
			 enum sasl_server_auth_flags auth_flags,
			 const char *init_resp)
{
	if (!client->secured && strcmp(client->ssl_set->ssl, "required") == 0) {
		if (client->set->auth_verbose) {
			e_info(client->event, "Login failed: "
			       "SSL required for authentication");
		}
		client->auth_attempts++;
		client_auth_result(client, CLIENT_AUTH_RESULT_SSL_REQUIRED, NULL,
			"Authentication not allowed until SSL/TLS is enabled.");
		return 1;
	}


	client_ref(client);
	client->auth_initializing = TRUE;
	sasl_server_auth_begin(client, mech_name, auth_flags,
			       init_resp, sasl_callback);
	client->auth_initializing = FALSE;
	if (!client->authenticating)
		return 1;

	/* don't handle input until we get the initial auth reply */
	io_remove(&client->io);
	client_set_auth_waiting(client);
	return 0;
}

int client_auth_begin(struct client *client, const char *mech_name,
		      const char *init_resp)
{
	return client_auth_begin_common(client, mech_name, 0, init_resp);
}

int client_auth_begin_private(struct client *client, const char *mech_name,
			      const char *init_resp)
{
	return client_auth_begin_common(client, mech_name,
					SASL_SERVER_AUTH_FLAG_PRIVATE,
					init_resp);
}

int client_auth_begin_implicit(struct client *client, const char *mech_name,
			       const char *init_resp)
{
	return client_auth_begin_common(client, mech_name,
					SASL_SERVER_AUTH_FLAG_IMPLICIT,
					init_resp);
}

bool client_check_plaintext_auth(struct client *client, bool pass_sent)
{
	bool ssl_required = (strcmp(client->ssl_set->ssl, "required") == 0);

	if (client->secured || (!client->set->disable_plaintext_auth &&
				!ssl_required))
		return TRUE;

	if (client->set->auth_verbose) {
		e_info(client->event, "Login failed: "
		       "Plaintext authentication disabled");
	}
	if (pass_sent) {
		client_notify_status(client, TRUE,
			 "Plaintext authentication not allowed "
			 "without SSL/TLS, but your client did it anyway. "
			 "If anyone was listening, the password was exposed.");
	}

	if (ssl_required) {
		client_auth_result(client, CLIENT_AUTH_RESULT_SSL_REQUIRED, NULL,
			   AUTH_PLAINTEXT_DISABLED_MSG);
	} else {
		client_auth_result(client, CLIENT_AUTH_RESULT_MECH_SSL_REQUIRED, NULL,
			   AUTH_PLAINTEXT_DISABLED_MSG);
	}
	client->auth_attempts++;
	return FALSE;
}

void clients_notify_auth_connected(void)
{
	struct client *client, *next;

	for (client = clients; client != NULL; client = next) {
		next = client->next;

		timeout_remove(&client->to_auth_waiting);

		client_notify_auth_ready(client);

		if (!client_does_custom_io(client) && client->input_blocked) {
			client->input_blocked = FALSE;
			io_set_pending(client->io);
		}
	}
}
