/* Copyright (c) 2011-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "ioloop.h"
#include "passdb.h"
#include "str.h"
#include "imap-resp-code.h"
#include "imapc-client.h"

#define DNS_CLIENT_SOCKET_NAME "dns-client"

struct passdb_imap_settings {
	pool_t pool;
};

static const struct setting_define passdb_imap_setting_defines[] = {
	{ .type = SET_FILTER_NAME, .key = "passdb_imapc" },

	SETTING_DEFINE_LIST_END,
};

const struct setting_parser_info passdb_imap_setting_parser_info = {
	.name = "auth_imapc",

	.defines = passdb_imap_setting_defines,

	.struct_size = sizeof(struct passdb_imap_settings),
	.pool_offset1 = 1 + offsetof(struct passdb_imap_settings, pool),
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
	struct imap_auth_request *request;
	struct imapc_parameters params = {
		.override_password = password,
	};

	if (auth_request_set_passdb_fields(auth_request, NULL) < 0) {
		callback(PASSDB_RESULT_INTERNAL_FAILURE, auth_request);
		return;
	}

	request = p_new(auth_request->pool, struct imap_auth_request, 1);
	request->client = imapc_client_init(&params, authdb_event(auth_request));
	request->auth_request = auth_request;
	request->verify_callback = callback;

	auth_request_ref(auth_request);
	imapc_client_set_login_callback(request->client, passdb_imap_login_callback, request);
	imapc_client_login(request->client);
}

static struct passdb_module_interface passdb_imap_plugin = {
	.name = "imap",
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
