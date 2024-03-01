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
	struct imapc_settings set;
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
	struct imapc_settings set;
	struct imapc_parameters params = {};
	const char *error;
	string_t *str;

	set = module->set;
	set.dns_client_socket_path =
		t_strconcat(auth_request->set->base_dir, "/",
			    DNS_CLIENT_SOCKET_NAME, NULL);
	set.imapc_password = password;
	set.imapc_max_idle_time = IMAPC_DEFAULT_MAX_IDLE_TIME;

	if (module->set_have_vars) {
		str = t_str_new(128);
		if (auth_request_var_expand(str, set.imapc_user, auth_request,
					    NULL, &error) <= 0) {
			e_error(authdb_event(auth_request),
				"Failed to expand username=%s: %s",
				set.imapc_user, error);
			callback(PASSDB_RESULT_INTERNAL_FAILURE, auth_request);
			return;
		}
		set.imapc_user = t_strdup(str_c(str));

		str_truncate(str, 0);
		if (auth_request_var_expand(str, set.imapc_host, auth_request,
					    NULL, &error) <= 0) {
			e_error(authdb_event(auth_request),
				"Failed to expand host=%s: %s",
				set.imapc_host, error);
			callback(PASSDB_RESULT_INTERNAL_FAILURE, auth_request);
			return;
		}
		set.imapc_host = t_strdup(str_c(str));
	}
	e_debug(authdb_event(auth_request),
		"lookup host=%s port=%d", set.imapc_host, set.imapc_port);

	request = p_new(auth_request->pool, struct imap_auth_request, 1);
	request->client = imapc_client_init(&set, &params, authdb_event(auth_request));
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
	module->set.imapc_port = IMAP_DEFAULT_PORT;
	module->set.imapc_ssl = "no";
	module->set.imapc_user = "%u";
	module->set.imapc_rawlog_dir = "";

	for (tmp = p_strsplit(pool, args, " "); *tmp != NULL; tmp++) {
		key = *tmp;
		value = strchr(key, '=');
		if (value == NULL)
			value = "";
		else
			key = t_strdup_until(key, value++);
		if (strcmp(key, "host") == 0)
			module->set.imapc_host = value;
		else if (strcmp(key, "port") == 0) {
			if (net_str2port(value, &module->set.imapc_port) < 0)
				i_fatal("passdb imap: Invalid port: %s", value);
			port_set = TRUE;
		} else if (strcmp(key, "username") == 0)
			module->set.imapc_user = value;
		else if (strcmp(key, "rawlog_dir") == 0)
			module->set.imapc_rawlog_dir = value;
		else if (strcmp(key, "ssl") == 0) {
			if (strcmp(value, "imaps") == 0) {
				if (!port_set)
					module->set.imapc_port = IMAPS_DEFAULT_PORT;
				module->set.imapc_ssl = "imaps";
			} else if (strcmp(value, "starttls") == 0) {
				module->set.imapc_ssl = "starttls";
			} else {
				i_fatal("passdb imap: Invalid ssl mode: %s",
					value);
			}
		} else {
			i_fatal("passdb imap: Unknown parameter: %s", key);
		}
	}

	if (module->set.imapc_host == NULL)
		i_fatal("passdb imap: Missing host parameter");

	module->set_have_vars =
		strchr(module->set.imapc_user, '%') != NULL ||
		strchr(module->set.imapc_host, '%') != NULL;
	return &module->module;
}

static struct passdb_module_interface passdb_imap_plugin = {
	.name = "imap",
	.preinit_legacy = passdb_imap_preinit,
	.verify_plain = passdb_imap_verify_plain,
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
