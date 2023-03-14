/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "sasl-server-protected.h" // FIXME: Use public API only
#include "auth.h"
#include "auth-common.h"
#include "auth-sasl.h"
#include "auth-request.h"

/*
 * Request
 */

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
