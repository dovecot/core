/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "ioloop.h"
#include "passdb.h"
#include "str.h"
#include "imap-resp-code.h"
#include "imapc-client.h"

#define IMAP_DEFAULT_PORT 143
#define IMAPS_DEFAULT_PORT 993
#define DNS_CLIENT_SOCKET_NAME "dns-client"

struct imap_passdb_module {
	struct passdb_module module;
	struct imapc_client_settings set;
	bool set_have_vars;
};

struct imap_auth_request {
	struct imapc_client *client;
	struct auth_request *auth_request;
	verify_plain_callback_t *verify_callback;
	struct timeout *to_free;
};

static enum passdb_result
passdb_imap_get_failure_result(const struct imapc_command_reply *reply)
{
	const char *key = reply->resp_text_key;

	if (key == NULL)
		return PASSDB_RESULT_PASSWORD_MISMATCH;

	if (strcasecmp(key, IMAP_RESP_CODE_AUTHFAILED) == 0 ||
	    strcasecmp(key, IMAP_RESP_CODE_AUTHZFAILED) == 0)
		return PASSDB_RESULT_PASSWORD_MISMATCH;
	if (strcasecmp(key, IMAP_RESP_CODE_EXPIRED) == 0)
		return PASSDB_RESULT_PASS_EXPIRED;
	return PASSDB_RESULT_INTERNAL_FAILURE;
}

static void passdb_imap_login_free(struct imap_auth_request *request)
{
	timeout_remove(&request->to_free);
	imapc_client_deinit(&request->client);
	auth_request_unref(&request->auth_request);
}

static void
passdb_imap_login_callback(const struct imapc_command_reply *reply,
			   void *context)
{
	struct imap_auth_request *request = context;
	enum passdb_result result = PASSDB_RESULT_INTERNAL_FAILURE;

	switch (reply->state) {
	case IMAPC_COMMAND_STATE_OK:
		result = PASSDB_RESULT_OK;
		break;
	case IMAPC_COMMAND_STATE_NO:
		result = passdb_imap_get_failure_result(reply);
		e_info(authdb_event(request->auth_request),
		       "%s", reply->text_full);
		break;
	case IMAPC_COMMAND_STATE_AUTH_FAILED:
	case IMAPC_COMMAND_STATE_BAD:
	case IMAPC_COMMAND_STATE_DISCONNECTED:
		e_error(authdb_event(request->auth_request),
			"%s", reply->text_full);
		break;
	}
	request->verify_callback(result, request->auth_request);
	/* imapc_client can't be freed in this callback, so do it in a
	   separate callback. FIXME: remove this once imapc supports proper
	   refcounting. */
	request->to_free = timeout_add_short(0, passdb_imap_login_free, request);
}

static void
passdb_imap_verify_plain(struct auth_request *auth_request,
			 const char *password,
			 verify_plain_callback_t *callback)
{
        struct passdb_module *_module = auth_request->passdb->passdb;
	struct imap_passdb_module *module =
		(struct imap_passdb_module *)_module;
	struct imap_auth_request *request;
	struct imapc_client_settings set;
	const char *error;
	string_t *str;

	set = module->set;
	set.debug = auth_request->debug;
	set.dns_client_socket_path =
		t_strconcat(auth_request->set->base_dir, "/",
			    DNS_CLIENT_SOCKET_NAME, NULL);
	set.password = password;
	set.max_idle_time = IMAPC_DEFAULT_MAX_IDLE_TIME;
	if (set.ssl_set.ca_dir == NULL)
		set.ssl_set.ca_dir = auth_request->set->ssl_client_ca_dir;
	if (set.ssl_set.ca_file == NULL)
		set.ssl_set.ca_file = auth_request->set->ssl_client_ca_file;

	if (module->set_have_vars) {
		str = t_str_new(128);
		if (auth_request_var_expand(str, set.username, auth_request,
					    NULL, &error) <= 0) {
			e_error(authdb_event(auth_request),
				"Failed to expand username=%s: %s",
				set.username, error);
			callback(PASSDB_RESULT_INTERNAL_FAILURE, auth_request);
			return;
		}
		set.username = t_strdup(str_c(str));

		str_truncate(str, 0);
		if (auth_request_var_expand(str, set.host, auth_request,
					    NULL, &error) <= 0) {
			e_error(authdb_event(auth_request),
				"Failed to expand host=%s: %s",
				set.host, error);
			callback(PASSDB_RESULT_INTERNAL_FAILURE, auth_request);
			return;
		}
		set.host = t_strdup(str_c(str));
	}
	e_debug(authdb_event(auth_request),
		"lookup host=%s port=%d", set.host, set.port);

	request = p_new(auth_request->pool, struct imap_auth_request, 1);
	request->client = imapc_client_init(&set);
	request->auth_request = auth_request;
	request->verify_callback = callback;

	auth_request_ref(auth_request);
	imapc_client_set_login_callback(request->client, passdb_imap_login_callback, request);
	imapc_client_login(request->client);
}

static struct passdb_module *
passdb_imap_preinit(pool_t pool, const char *args)
{
	struct imap_passdb_module *module;
	char **tmp;
	const char *key, *value;
	bool port_set = FALSE;

	module = p_new(pool, struct imap_passdb_module, 1);
	module->module.default_pass_scheme = "PLAIN";
	module->set.port = IMAP_DEFAULT_PORT;
	module->set.ssl_mode = IMAPC_CLIENT_SSL_MODE_NONE;
	module->set.username = "%u";
	module->set.rawlog_dir = "";

	for (tmp = p_strsplit(pool, args, " "); *tmp != NULL; tmp++) {
		key = *tmp;
		value = strchr(key, '=');
		if (value == NULL)
			value = "";
		else
			key = t_strdup_until(key, value++);
		if (strcmp(key, "host") == 0)
			module->set.host = value;
		else if (strcmp(key, "port") == 0) {
			if (net_str2port(value, &module->set.port) < 0)
				i_fatal("passdb imap: Invalid port: %s", value);
			port_set = TRUE;
		} else if (strcmp(key, "username") == 0)
			module->set.username = value;
		else if (strcmp(key, "ssl_ca_dir") == 0)
			module->set.ssl_set.ca_dir = value;
		else if (strcmp(key, "ssl_ca_file") == 0)
			module->set.ssl_set.ca_file = value;
		else if (strcmp(key, "rawlog_dir") == 0)
			module->set.rawlog_dir = value;
		else if (strcmp(key, "ssl") == 0) {
			if (strcmp(value, "imaps") == 0) {
				if (!port_set)
					module->set.port = IMAPS_DEFAULT_PORT;
				module->set.ssl_mode =
					IMAPC_CLIENT_SSL_MODE_IMMEDIATE;
			} else if (strcmp(value, "starttls") == 0) {
				module->set.ssl_mode =
					IMAPC_CLIENT_SSL_MODE_STARTTLS;
			} else {
				i_fatal("passdb imap: Invalid ssl mode: %s",
					value);
			}
		} else if (strcmp(key, "allow_invalid_cert") == 0) {
			if (strcmp(value, "yes") == 0) {
				module->set.ssl_set.allow_invalid_cert = TRUE;
			} else if (strcmp(value, "no") == 0) {
				module->set.ssl_set.allow_invalid_cert = FALSE;
			} else {
				i_fatal("passdb imap: Invalid allow_invalid_cert value: %s",
					value);
			}
		} else {
			i_fatal("passdb imap: Unknown parameter: %s", key);
		}
	}

	if (!module->set.ssl_set.allow_invalid_cert && module->set.ssl_mode != IMAPC_CLIENT_SSL_MODE_NONE) {
		if (module->set.ssl_set.ca_dir == NULL && module->set.ssl_set.ca_file == NULL)
			i_fatal("passdb imap: Cannot verify certificate without ssl_ca_dir or ssl_ca_file setting");
	}

	if (module->set.host == NULL)
		i_fatal("passdb imap: Missing host parameter");

	module->set_have_vars =
		strchr(module->set.username, '%') != NULL ||
		strchr(module->set.host, '%') != NULL;
	return &module->module;
}

static struct passdb_module_interface passdb_imap_plugin = {
	"imap",

	passdb_imap_preinit,
	NULL,
	NULL,

	passdb_imap_verify_plain,
	NULL,
	NULL
};

void authdb_imap_init(void);
void authdb_imap_deinit(void);

void authdb_imap_init(void)
{
	passdb_register_module(&passdb_imap_plugin);

}
void authdb_imap_deinit(void)
{
	passdb_unregister_module(&passdb_imap_plugin);
}
