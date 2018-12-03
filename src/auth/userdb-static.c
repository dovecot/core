/* Copyright (c) 2003-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"

#include "array.h"
#include "str.h"
#include "var-expand.h"
#include "userdb.h"
#include "userdb-template.h"


struct static_context {
	userdb_callback_t *callback, *old_callback;
	void *old_context;
};

struct static_userdb_module {
	struct userdb_module module;
	struct userdb_template *tmpl;

	bool allow_all_users:1;
};

static void static_lookup_real(struct auth_request *auth_request,
			       userdb_callback_t *callback)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct static_userdb_module *module =
		(struct static_userdb_module *)_module;
	const char *error;

	if (userdb_template_export(module->tmpl, auth_request, &error) < 0) {
		e_error(authdb_event(auth_request),
			"Failed to expand template: %s", error);
		callback(USERDB_RESULT_INTERNAL_FAILURE, auth_request);
	}
	callback(USERDB_RESULT_OK, auth_request);
}

static void
static_credentials_callback(enum passdb_result result,
			    const unsigned char *credentials ATTR_UNUSED,
			    size_t size ATTR_UNUSED,
			    struct auth_request *auth_request)
{
	struct static_context *ctx = auth_request->context;

	auth_request->userdb_lookup = TRUE;

	auth_request->private_callback.userdb = ctx->old_callback;
	auth_request->context = ctx->old_context;
	auth_request_set_state(auth_request, AUTH_REQUEST_STATE_USERDB);

	switch (result) {
	case PASSDB_RESULT_OK:
		static_lookup_real(auth_request, ctx->callback);
		break;
	case PASSDB_RESULT_USER_UNKNOWN:
	case PASSDB_RESULT_USER_DISABLED:
	case PASSDB_RESULT_PASS_EXPIRED:
		ctx->callback(USERDB_RESULT_USER_UNKNOWN, auth_request);
		break;
	case PASSDB_RESULT_SCHEME_NOT_AVAILABLE:
		e_error(authdb_event(auth_request),
			"passdb doesn't support lookups, "
			"can't verify user's existence");
		/* fall through */
	default:
		ctx->callback(USERDB_RESULT_INTERNAL_FAILURE, auth_request);
		break;
	}

	i_free(ctx);
}

static void static_lookup(struct auth_request *auth_request,
			  userdb_callback_t *callback)
{
	struct userdb_module *_module = auth_request->userdb->userdb;
	struct static_userdb_module *module =
		(struct static_userdb_module *)_module;
	struct static_context *ctx;

	if (!auth_request->successful && !module->allow_all_users) {
		/* this is a userdb-only lookup. we need to know if this
		   users exists or not. use a passdb lookup to do that.
		   if the passdb doesn't support returning credentials, this
		   will of course fail.. */
		ctx = i_new(struct static_context, 1);
		ctx->old_callback = auth_request->private_callback.userdb;
		ctx->old_context = auth_request->context;
		ctx->callback = callback;

		i_assert(auth_request->state == AUTH_REQUEST_STATE_USERDB);
		auth_request_set_state(auth_request,
				       AUTH_REQUEST_STATE_MECH_CONTINUE);

		auth_request->context = ctx;
		if (auth_request->passdb != NULL) {
			/* kludge: temporarily work as if we weren't doing
			   a userdb lookup. this is to get auth cache to use
			   passdb caching instead of userdb caching. */
			auth_request->userdb_lookup = FALSE;
			auth_request_lookup_credentials(auth_request, "",
				static_credentials_callback);
		} else {
			static_credentials_callback(
				PASSDB_RESULT_SCHEME_NOT_AVAILABLE,
				uchar_empty_ptr, 0, auth_request);
		}
	} else {
		static_lookup_real(auth_request, callback);
	}
}

static struct userdb_module *
static_preinit(pool_t pool, const char *args)
{
	struct static_userdb_module *module;
	const char *value;

	module = p_new(pool, struct static_userdb_module, 1);
	module->tmpl = userdb_template_build(pool, "static", args);

	if (userdb_template_remove(module->tmpl, "allow_all_users", &value)) {
		module->allow_all_users = value == NULL ||
			strcasecmp(value, "yes") == 0;
	}
	return &module->module;
}

struct userdb_module_interface userdb_static = {
	"static",

	static_preinit,
	NULL,
	NULL,

	static_lookup,

	NULL,
	NULL,
	NULL
};
