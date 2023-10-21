/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "settings-parser.h"
#include "sasl-server-protected.h" // FIXME: remove
#include "auth.h"
#include "auth-common.h"
#include "auth-sasl.h"
#include "auth-sasl-oauth2.h"
#include "auth-request.h"
#include "auth-request-handler.h"

#include <ctype.h>

static struct sasl_server *auth_sasl_server;

static char *auth_sasl_mechs_handshake;
static char *auth_sasl_mechs_handshake_cbind;

/*
 * Request
 */

static bool
auth_sasl_request_set_authid(struct sasl_server_req_ctx *rctx,
			     enum sasl_server_authid_type authid_type,
			     const char *authid)
{
	struct auth_request *request =
		container_of(rctx, struct auth_request, sasl.req);
	const char *error;

	switch (authid_type) {
	case SASL_SERVER_AUTHID_TYPE_USERNAME:
		if (request->fields.realm != NULL &&
		    strchr(authid, '@') == NULL) {
			authid = t_strconcat(
				authid, "@", request->fields.realm, NULL);
			request->domain_is_realm = TRUE;
		}
		if (!auth_request_set_username(request, authid, &error)) {
			e_info(request->event, "%s", error);
			return FALSE;
		}
		return TRUE;
	case SASL_SERVER_AUTHID_TYPE_ANONYMOUS:
		i_assert(*request->set->anonymous_username != '\0');

		/* Temporarily set the user to the one that was given, so that
		   the log  message goes right */
		auth_request_set_username_forced(request, authid);
		e_info(request->event, "anonymous login");
		auth_request_set_username_forced(
			request, request->set->anonymous_username);
		return TRUE;
	case SASL_SERVER_AUTHID_TYPE_EXTERNAL:
		i_assert(authid == NULL || *authid == '\0');
		if (request->fields.user == NULL) {
			e_info(request->event, "Username not known");
			return FALSE;
		}

		/* This call is done simply to put the username through
		   translation settings */
		if (!auth_request_set_username(request, "", &error)) {
			e_info(request->event, "Invalid username");
			return FALSE;
		}
		return TRUE;
	}
	i_unreached();
}

static bool
auth_sasl_request_set_authzid(struct sasl_server_req_ctx *rctx,
			      const char *authzid)
{
	struct auth_request *request =
		container_of(rctx, struct auth_request, sasl.req);
	const char *error;

	if (!auth_request_set_login_username(request, authzid, &error)) {
		e_info(request->event, "login user: %s", error);
		return FALSE;
	}
	return TRUE;
}

static void
auth_sasl_request_set_realm(struct sasl_server_req_ctx *rctx,
			    const char *realm)
{
	struct auth_request *request =
		container_of(rctx, struct auth_request, sasl.req);

	auth_request_set_realm(request, realm);
}

static bool
auth_sasl_request_get_extra_field(struct sasl_server_req_ctx *rctx,
				  const char *name, const char **field_r)
{
	struct auth_request *request =
		container_of(rctx, struct auth_request, sasl.req);
	const char *value;

	value = auth_fields_find(request->fields.extra_fields, name);
	if (value == NULL)
		return FALSE;

	*field_r = value;
	return TRUE;
}

static void
auth_sasl_request_start_channel_binding(struct sasl_server_req_ctx *rctx,
					const char *type)
{
	struct auth_request *request =
		container_of(rctx, struct auth_request, sasl.req);

	auth_request_start_channel_binding(request, type);
}

static int
auth_sasl_request_accept_channel_binding(struct sasl_server_req_ctx *rctx,
					 buffer_t **data_r)
{
	struct auth_request *request =
		container_of(rctx, struct auth_request, sasl.req);

	return auth_request_accept_channel_binding(request, data_r);
}

static void
auth_sasl_request_output(struct sasl_server_req_ctx *rctx,
			 const struct sasl_server_output *output)
{
	struct auth_request *request =
		container_of(rctx, struct auth_request, sasl.req);

	switch (output->status) {
	case SASL_SERVER_OUTPUT_INTERNAL_FAILURE:
		auth_request_internal_failure(request);
		break;
	case SASL_SERVER_OUTPUT_FAILURE:
		auth_request_fail(request);
		break;
	case SASL_SERVER_OUTPUT_CONTINUE:
		auth_request_handler_reply_continue(request, output->data,
						    output->data_size);
		break;
	case SASL_SERVER_OUTPUT_SUCCESS:
		if (sasl_server_mech_get_passdb_need(rctx->mech) ==
				SASL_MECH_PASSDB_NEED_NOTHING)
			request->passdb_success = TRUE;

		auth_request_success(request, output->data, output->data_size);
		break;
	}
}

static enum sasl_passdb_result_status
translate_result_status(enum passdb_result result)
{
	switch (result) {
	case PASSDB_RESULT_INTERNAL_FAILURE:;
		return SASL_PASSDB_RESULT_INTERNAL_FAILURE;
	case PASSDB_RESULT_SCHEME_NOT_AVAILABLE:
		return SASL_PASSDB_RESULT_SCHEME_NOT_AVAILABLE;
	case PASSDB_RESULT_USER_UNKNOWN:
		return SASL_PASSDB_RESULT_USER_UNKNOWN;
	case PASSDB_RESULT_USER_DISABLED:
		return SASL_PASSDB_RESULT_USER_DISABLED;
	case PASSDB_RESULT_PASS_EXPIRED:
		return SASL_PASSDB_RESULT_PASS_EXPIRED;
	case PASSDB_RESULT_PASSWORD_MISMATCH:
		return SASL_PASSDB_RESULT_PASSWORD_MISMATCH;
	case PASSDB_RESULT_NEXT:
	case PASSDB_RESULT_OK:
		return SASL_PASSDB_RESULT_OK;
	}
	i_unreached();
}

static void
verify_plain_callback(enum passdb_result status, struct auth_request *request)
{
	const struct sasl_passdb_result result = {
		.status = translate_result_status(status),
	};
	request->sasl.passdb_callback(&request->sasl.req, &result);
}

static void
auth_sasl_request_verify_plain(struct sasl_server_req_ctx *rctx,
			       const char *password,
			       sasl_server_passdb_callback_t *callback)
{
	struct auth_request *request =
		container_of(rctx, struct auth_request, sasl.req);

	request->sasl.passdb_callback = callback;
	auth_request_verify_plain(request, password, verify_plain_callback);
}

static void
lookup_credentials_callback(enum passdb_result status,
			    const unsigned char *credentials, size_t size,
			    struct auth_request *request)
{
	const struct sasl_passdb_result result = {
		.status = translate_result_status(status),
		.credentials = {
			.data = credentials,
			.size = size,
		},
	};
	request->sasl.passdb_callback(&request->sasl.req, &result);
}

static void
auth_sasl_request_lookup_credentials(struct sasl_server_req_ctx *rctx,
				     const char *scheme,
				     sasl_server_passdb_callback_t *callback)
{
	struct auth_request *request =
		container_of(rctx, struct auth_request, sasl.req);

	request->sasl.passdb_callback = callback;
	auth_request_lookup_credentials(request, scheme,
					lookup_credentials_callback);
}

static void
set_credentials_callback(bool success, struct auth_request *request)
{
	const struct sasl_passdb_result result = {
		.status = (success ?
			   SASL_PASSDB_RESULT_OK :
			   SASL_PASSDB_RESULT_INTERNAL_FAILURE),
	};
	request->sasl.passdb_callback(&request->sasl.req, &result);
}

static void
auth_sasl_request_set_credentials(struct sasl_server_req_ctx *rctx,
				  const char *scheme, const char *data,
				  sasl_server_passdb_callback_t *callback)
{
	struct auth_request *request =
		container_of(rctx, struct auth_request, sasl.req);

	request->sasl.passdb_callback = callback;
	auth_request_set_credentials(request, scheme, data,
				     set_credentials_callback);
}

static const struct sasl_server_request_funcs auth_sasl_request_funcs = {
	.request_set_authid = auth_sasl_request_set_authid,
	.request_set_authzid = auth_sasl_request_set_authzid,
	.request_set_realm = auth_sasl_request_set_realm,

	.request_get_extra_field = auth_sasl_request_get_extra_field,

	.request_start_channel_binding =
		auth_sasl_request_start_channel_binding,
	.request_accept_channel_binding =
		auth_sasl_request_accept_channel_binding,

	.request_output = auth_sasl_request_output,

	.request_verify_plain = auth_sasl_request_verify_plain,
	.request_lookup_credentials = auth_sasl_request_lookup_credentials,
	.request_set_credentials = auth_sasl_request_set_credentials,
};

static const char *
auth_sasl_translate_protocol_name(struct auth_request *request)
{
	i_assert(request->fields.protocol != NULL);

	const char *protocol = request->fields.protocol;

	/* Translate to SASL/GSSAPI/Kerberos service name (IANA-registered) */
	if (strcasecmp(protocol, "POP3") == 0) {
		/* The standard POP3 service name with SASL/GSSAPI/Kerberos is
		   called just "pop". */
		return "pop";
	}
	if (strcasecmp(protocol, "Submission") == 0 ||
	    strcasecmp(protocol, "LMTP") == 0) {
		/* The standard Submission or LMTP service name with
		   SASL/GSSAPI/Kerberos is called just "smtp". */
		return "smtp";
	}

	return t_str_lcase(protocol);
}

void auth_sasl_request_init(struct auth_request *request,
			    const struct sasl_server_mech *mech)
{
	sasl_server_request_create(&request->sasl.req, mech,
				   auth_sasl_translate_protocol_name(request),
				   request->mech_event);
}

void auth_sasl_request_deinit(struct auth_request *request)
{
	sasl_server_request_destroy(&request->sasl.req);
}

void auth_sasl_request_initial(struct auth_request *request)
{
	sasl_server_request_initial(&request->sasl.req,
				    request->initial_response,
				    request->initial_response_len);
}

void auth_sasl_request_continue(struct auth_request *request,
				const unsigned char *data, size_t data_size)
{
	sasl_server_request_input(&request->sasl.req, data, data_size);
}

/*
 * Mechanisms
 */

struct auth_sasl_mech_module_list {
	struct auth_sasl_mech_module_list *next;

	struct auth_sasl_mech_module module;
};

static struct auth_sasl_mech_module_list *auth_sasl_mech_modules;

void auth_sasl_mech_register_module(
	const struct auth_sasl_mech_module *module)
{
	struct auth_sasl_mech_module_list *list;

	i_assert(strcmp(module->mech_name,
			t_str_ucase(module->mech_name)) == 0);

	list = i_new(struct auth_sasl_mech_module_list, 1);
	list->module = *module;

	list->next = auth_sasl_mech_modules;
	auth_sasl_mech_modules = list;
}

void auth_sasl_mech_unregister_module(
	const struct auth_sasl_mech_module *module)
{
	struct auth_sasl_mech_module_list **pos, *list;

	for (pos = &auth_sasl_mech_modules; *pos != NULL; pos = &(*pos)->next) {
		if (strcmp((*pos)->module.mech_name, module->mech_name) == 0) {
			list = *pos;
			*pos = (*pos)->next;
			i_free(list);
			break;
		}
	}
}

const struct auth_sasl_mech_module *
auth_sasl_mech_module_find(const char *name)
{
	struct auth_sasl_mech_module_list *list;
	name = t_str_ucase(name);

	for (list = auth_sasl_mech_modules; list != NULL; list = list->next) {
		if (strcmp(list->module.mech_name, name) == 0)
			return &list->module;
	}
	return NULL;
}

const char *auth_sasl_mechs_get_handshake(void)
{
	return auth_sasl_mechs_handshake;
}

const char *auth_sasl_mechs_get_handshake_cbind(void)
{
	return auth_sasl_mechs_handshake_cbind;
}

/*
 * Instance
 */

static const char *auth_sasl_mech_get_plugin_name(const char *name);

void auth_sasl_instance_init(struct auth *auth,
			     const struct auth_settings *set)
{
	const struct sasl_server_settings sasl_set = {
		.realms = settings_boollist_get(&set->realms),
		.event_parent = auth_event,
		.verbose = set->verbose,
	};

	auth->sasl_inst =
		sasl_server_instance_create(auth_sasl_server, &sasl_set);

	const struct sasl_server_mech_def *mech;
	const char *name;

	if (array_is_empty(&set->mechanisms))
		i_fatal("No authentication mechanisms configured");

	array_foreach_elem(&set->mechanisms, name) {
		name = t_str_ucase(name);

		if (strcmp(name, SASL_MECH_NAME_ANONYMOUS) == 0) {
			if (*set->anonymous_username == '\0') {
				i_fatal("ANONYMOUS listed in mechanisms, "
					"but anonymous_username not set");
			}
		}
		mech = mech_module_find(name);
		if (mech == NULL) {
			/* maybe it's a plugin. try to load it. */
			auth_module_load(auth_sasl_mech_get_plugin_name(name));
			mech = mech_module_find(name);
		}
		if (mech == NULL)
			i_fatal("Unknown authentication mechanism '%s'", name);
		sasl_server_mech_register(auth->sasl_inst, mech);
	}

	auth->sasl_mech_dovecot_token =
		sasl_server_mech_register(auth->sasl_inst, &mech_dovecot_token);
}

static bool
auth_sasl_mech_verify_passdb(const struct auth *auth,
			     enum sasl_mech_passdb_need passdb_need)
{
	switch (passdb_need) {
	case SASL_MECH_PASSDB_NEED_NOTHING:
		break;
	case SASL_MECH_PASSDB_NEED_VERIFY_PLAIN:
		if (!auth_passdb_list_have_verify_plain(auth))
			return FALSE;
		break;
	case SASL_MECH_PASSDB_NEED_VERIFY_RESPONSE:
	case SASL_MECH_PASSDB_NEED_LOOKUP_CREDENTIALS:
		if (!auth_passdb_list_have_lookup_credentials(auth))
			return FALSE;
		break;
	case SASL_MECH_PASSDB_NEED_SET_CREDENTIALS:
		if (!auth_passdb_list_have_lookup_credentials(auth))
			return FALSE;
		if (!auth_passdb_list_have_set_credentials(auth))
			return FALSE;
		break;
	}
	return TRUE;
}

void auth_sasl_instance_verify(const struct auth *auth)
{
	struct sasl_server_mech_iter *mech_iter;

	mech_iter = sasl_server_instance_mech_iter_new(auth->sasl_inst);
	while (sasl_server_mech_iter_next(mech_iter)) {
		if (!auth_sasl_mech_verify_passdb(auth, mech_iter->passdb_need))
			break;
	}

	if (!sasl_server_mech_iter_ended(mech_iter)) {
		if (auth->passdbs == NULL) {
			i_fatal("No passdbs specified in configuration file. "
				"%s mechanism needs one",
				mech_iter->name);
		}
		i_fatal("%s mechanism can't be supported with given passdbs",
			mech_iter->name);
	}

	sasl_server_mech_iter_free(&mech_iter);
}

void auth_sasl_instance_deinit(struct auth *auth)
{
	sasl_server_instance_unref(&auth->sasl_inst);
}

/*
 * Global
 */

static void auth_sasl_mechs_handshake_init(void)
{
	struct sasl_server_mech_iter *iter;
	string_t *handshake_buf = t_str_new(512);
	string_t *handshake_buf_cbind = t_str_new(256);

	iter = sasl_server_mech_iter_new(auth_sasl_server);
	while (sasl_server_mech_iter_next(iter)) {
		string_t *handshake;

		if ((iter->flags & SASL_MECH_SEC_CHANNEL_BINDING) != 0)
			handshake = handshake_buf_cbind;
		else
			handshake = handshake_buf;

		str_printfa(handshake, "MECH\t%s", iter->name);
		if ((iter->flags & SASL_MECH_SEC_PRIVATE) != 0)
			str_append(handshake, "\tprivate");
		if ((iter->flags & SASL_MECH_SEC_ANONYMOUS) != 0)
			str_append(handshake, "\tanonymous");
		if ((iter->flags & SASL_MECH_SEC_PLAINTEXT) != 0)
			str_append(handshake, "\tplaintext");
		if ((iter->flags & SASL_MECH_SEC_DICTIONARY) != 0)
			str_append(handshake, "\tdictionary");
		if ((iter->flags & SASL_MECH_SEC_ACTIVE) != 0)
			str_append(handshake, "\tactive");
		if ((iter->flags & SASL_MECH_SEC_FORWARD_SECRECY) != 0)
			str_append(handshake, "\tforward-secrecy");
		if ((iter->flags & SASL_MECH_SEC_MUTUAL_AUTH) != 0)
			str_append(handshake, "\tmutual-auth");
		if ((iter->flags & SASL_MECH_SEC_CHANNEL_BINDING) != 0)
			str_append(handshake, "\tchannel-binding");
		str_append_c(handshake, '\n');
	}
	sasl_server_mech_iter_free(&iter);

	auth_sasl_mechs_handshake = i_strdup(str_c(handshake_buf));
	auth_sasl_mechs_handshake_cbind = i_strdup(str_c(handshake_buf_cbind));
}

static void auth_sasl_mechs_handshake_deinit(void)
{
	i_free(auth_sasl_mechs_handshake);
	i_free(auth_sasl_mechs_handshake_cbind);
}

static const char *auth_sasl_mech_get_plugin_name(const char *name)
{
	string_t *str = t_str_new(32);

	str_append(str, "mech_");
	for (; *name != '\0'; name++) {
		if (*name == '-')
			str_append_c(str, '_');
		else
			str_append_c(str, i_tolower(*name));
	}
	return str_c(str);
}

void auth_sasl_preinit(void)
{
	auth_sasl_oauth2_initialize();
	auth_sasl_server = sasl_server_init(auth_event,
					    &auth_sasl_request_funcs);
}

void auth_sasl_init(void)
{
	auth_sasl_mechs_handshake_init();
}

void auth_sasl_deinit(void)
{
	sasl_server_deinit(&auth_sasl_server);
	auth_sasl_mechs_handshake_deinit();
}
