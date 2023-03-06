/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "sasl-server-protected.h" // FIXME: Use public API only
#include "sasl-server.h"
#include "auth.h"
#include "auth-common.h"
#include "auth-sasl.h"
#include "auth-request.h"

/*
 * Request
 */

bool
auth_sasl_request_set_authid(struct auth_request *request,
			     enum sasl_server_authid_type authid_type,
			     const char *authid)
{
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

bool
auth_sasl_request_set_authzid(struct auth_request *request,
			      const char *authzid)
{
	const char *error;

	if (!auth_request_set_login_username(request, authzid, &error)) {
		e_info(request->event, "login user: %s", error);
		return FALSE;
	}
	return TRUE;
}

void
auth_sasl_request_set_realm(struct auth_request *request,
			    const char *realm)
{
	auth_request_set_realm(request, realm);
}

bool
auth_sasl_request_get_extra_field(struct auth_request *request,
				  const char *name, const char **field_r)
{
	const char *value;

	value = auth_fields_find(request->fields.extra_fields, name);
	if (value == NULL)
		return FALSE;

	*field_r = value;
	return TRUE;
}

void
auth_sasl_request_start_channel_binding(struct auth_request *request,
					const char *type)
{
	auth_request_start_channel_binding(request, type);
}

int
auth_sasl_request_accept_channel_binding(struct auth_request *request,
					 buffer_t **data_r)
{
	return auth_request_accept_channel_binding(request, data_r);
}

void
auth_sasl_request_output(struct auth_request *request,
			 const struct sasl_server_output *output)
{
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
		auth_request_success(request, output->data, output->data_size);
		break;
	}
}

void
auth_sasl_request_verify_plain(struct auth_request *request,
			       const char *password,
			       verify_plain_callback_t *verify_plain_callback)
{
	auth_request_verify_plain(request, password, verify_plain_callback);
}

void
auth_sasl_request_lookup_credentials(struct auth_request *request,
				     const char *scheme,
				     lookup_credentials_callback_t *lookup_credentials_callback)
{
	auth_request_lookup_credentials(request, scheme,
					lookup_credentials_callback);
}

void
auth_sasl_request_set_credentials(struct auth_request *request,
				  const char *scheme, const char *data,
				  set_credentials_callback_t  *set_credentials_callback)
{
	auth_request_set_credentials(request, scheme, data,
				     set_credentials_callback);
}

void auth_sasl_request_init(struct auth_request *request,
			    const struct sasl_server_mech_def *mech)
{
	sasl_server_request_create(request, mech, request->mech_event);
}

void auth_sasl_request_deinit(struct auth_request *request)
{
	sasl_server_request_destroy(request);
}

void auth_sasl_request_initial(struct auth_request *request)
{
	request->mech->auth_initial(request->sasl, request->initial_response,
				    request->initial_response_len);
}

void auth_sasl_request_continue(struct auth_request *request,
				const unsigned char *data, size_t data_size)
{
       request->mech->auth_continue(request->sasl, data, data_size);
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
