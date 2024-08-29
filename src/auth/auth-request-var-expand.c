/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "str.h"
#include "strescape.h"
#include "settings.h"
#include "auth-request.h"

struct auth_request_var_expand_ctx {
	const struct auth_request *auth_request;
	auth_request_escape_func_t *escape_func;
};

const struct var_expand_table
auth_request_var_expand_static_tab[] = {
	{ .key = "user", .value = NULL },
	{ .key = "protocol", .value = NULL },
	{ .key = "home", .value = NULL },
	{ .key = "local_ip", .value = NULL },
	{ .key = "remote_ip", .value = NULL },
	{ .key = "client_pid", .value = NULL },
	{ .key = "password", .value = NULL },
	{ .key = "id", .value = NULL },
	{ .key = "mechanism", .value = NULL },
	{ .key = "secured", .value = NULL },
	{ .key = "local_port", .value = NULL },
	{ .key = "remote_port", .value = NULL },
	{ .key = "cert", .value = NULL },
	{ .key = "login_user", .value = NULL },
	{ .key = "session", .value = NULL },
	{ .key = "real_local_ip", .value = NULL },
	{ .key = "real_remote_ip", .value = NULL },
	{ .key = "real_local_port", .value = NULL },
	{ .key = "real_remote_port", .value = NULL },
	{ .key = "domain_first", .value = NULL },
	{ .key = "domain_last", .value = NULL },
	{ .key = "master_user", .value = NULL },
	{ .key = "session_pid", .value = NULL },
	{ .key = "original_user", .value = NULL },
	{ .key = "auth_user", .value = NULL },
	{ .key = "local_name", .value = NULL },
	{ .key = "client_id", .value = NULL },
	{ .key = "ssl_ja3_hash", .value = NULL },
	{ .key = "owner_user", .value = NULL },
	VAR_EXPAND_TABLE_END
	/* be sure to update AUTH_REQUEST_VAR_TAB_COUNT */
};
static_assert_array_size(auth_request_var_expand_static_tab,
			 AUTH_REQUEST_VAR_TAB_COUNT+1);

static const char *
escape_none(const char *string,
	    const struct auth_request *request ATTR_UNUSED)
{
	return string;
}

const char *
auth_request_str_escape(const char *string,
			const struct auth_request *request ATTR_UNUSED)
{
	return str_escape(string);
}

struct var_expand_table *
auth_request_get_var_expand_table_full(const struct auth_request *auth_request,
				       const char *username,
				       unsigned int *count)
{
	const struct auth_request_fields *fields = &auth_request->fields;
	const unsigned int auth_count =
		N_ELEMENTS(auth_request_var_expand_static_tab);
	struct var_expand_table *tab, *ret_tab;
	const char *orig_user, *auth_user;

	/* keep the extra fields at the beginning. the last static_tab field
	   contains the ending NULL-fields. */
	tab = ret_tab = t_new(struct var_expand_table,
			      MALLOC_ADD(*count, auth_count));
	tab += *count;
	*count += auth_count;

	memcpy(tab, auth_request_var_expand_static_tab,
	       auth_count * sizeof(*tab));

	if (username == NULL)
		username = "";

	var_expand_table_set_value(tab, "user", username);
	var_expand_table_set_value(tab, "protocol", fields->protocol);
	/* tab['home'] = we have no home dir */
	if (fields->local_ip.family != 0) {
		var_expand_table_set_value(tab, "local_ip",
				net_ip2addr(&fields->local_ip));
	}
	if (fields->remote_ip.family != 0) {
		var_expand_table_set_value(tab, "remote_ip",
			net_ip2addr(&fields->remote_ip));
	}
	var_expand_table_set_value(tab, "client_pid",
			dec2str(auth_request->client_pid));
	var_expand_table_set_value(tab, "password", auth_request->mech_password);
	if (auth_request->userdb_lookup) {
		var_expand_table_set_value(tab, "id",
				auth_request->userdb == NULL ? "" :
				dec2str(auth_request->userdb->userdb->id));
	} else {
		var_expand_table_set_value(tab, "id",
				auth_request->passdb == NULL ? "" :
				dec2str(auth_request->passdb->passdb->id));
	}

	var_expand_table_set_value(tab, "mechanism", fields->mech_name);

	switch (fields->conn_secured) {
	case AUTH_REQUEST_CONN_SECURED_NONE:
		var_expand_table_set_value(tab, "secured", ""); break;
	case AUTH_REQUEST_CONN_SECURED:
		var_expand_table_set_value(tab, "secured", "secured"); break;
	case AUTH_REQUEST_CONN_SECURED_TLS:
		var_expand_table_set_value(tab, "secured", "TLS"); break;
	default:
		var_expand_table_set_value(tab, "secured", ""); break;
	};

	var_expand_table_set_value(tab, "local_port", dec2str(fields->local_port));
	var_expand_table_set_value(tab, "remote_port", dec2str(fields->remote_port));
	var_expand_table_set_value(tab, "cert",
			fields->valid_client_cert ? "valid" : "");

	var_expand_table_set_value(tab, "login_user", fields->requested_login_user);

	var_expand_table_set_value(tab, "session", fields->session_id);
	if (fields->real_local_ip.family != 0) {
		var_expand_table_set_value(tab, "real_local_ip",
			net_ip2addr(&fields->real_local_ip));
	}
	if (fields->real_remote_ip.family != 0) {
		var_expand_table_set_value(tab, "real_remote_ip",
			net_ip2addr(&fields->real_remote_ip));
	}
	var_expand_table_set_value(tab, "real_local_port",
				   dec2str(fields->real_local_port));
	var_expand_table_set_value(tab, "real_remote_port",
				   dec2str(fields->real_remote_port));

	const char *domain_first = i_strchr_to_next(username, '@');
	if (domain_first != NULL)
		domain_first = t_strcut(domain_first, '@');
	var_expand_table_set_value(tab, "domain_first", domain_first);
	const char *domain_last = strrchr(username, '@');
	if (domain_last != NULL)
		domain_last++;
	var_expand_table_set_value(tab, "domain_last", domain_last);
	var_expand_table_set_value(tab, "master_user", fields->master_user);

	const char *session_pid = "";
	if (auth_request->session_pid != (pid_t)-1)
		session_pid = dec2str(auth_request->session_pid);
	var_expand_table_set_value(tab, "session_pid", session_pid);

	orig_user = fields->original_username != NULL ?
		fields->original_username : username;
	var_expand_table_set_value(tab, "original_user", orig_user);

	auth_user = fields->master_user != NULL ?
		fields->master_user : orig_user;
	var_expand_table_set_value(tab, "auth_user", auth_user);
	var_expand_table_set_value(tab, "local_name", fields->local_name);
	var_expand_table_set_value(tab, "client_id", fields->client_id);
	var_expand_table_set_value(tab, "ssl_ja3_hash", fields->ssl_ja3_hash);
	var_expand_table_set_value(tab, "owner_user", username);
	return ret_tab;
}

const struct var_expand_table *
auth_request_get_var_expand_table(const struct auth_request *auth_request)
{
	unsigned int count = 0;

	return auth_request_get_var_expand_table_full(auth_request,
		auth_request->fields.user, &count);
}

static int
auth_request_var_expand_func_passdb(const char *field_name, const char **value_r,
				    void *context,
				    const char **error_r ATTR_UNUSED)
{
	struct auth_request_var_expand_ctx *ctx = context;
	const char *value;

	value = auth_fields_find(ctx->auth_request->fields.extra_fields, field_name);
	if (value == NULL)
		value = "";
	*value_r = value;
	return 0;
}

static int
auth_request_var_expand_func_userdb(const char *field_name, const char **value_r,
				    void *context, const char **error_r ATTR_UNUSED)
{
	struct auth_request_var_expand_ctx *ctx = context;
	const char *value;

	value = ctx->auth_request->fields.userdb_reply == NULL ? NULL :
		auth_fields_find(ctx->auth_request->fields.userdb_reply, field_name);
	if (value == NULL)
		value = "";
	*value_r = value;
	return 0;
}

const struct var_expand_provider auth_request_var_expand_providers[] = {
	{ .key = "passdb", .func = auth_request_var_expand_func_passdb },
	{ .key = "userdb", .func = auth_request_var_expand_func_userdb },
	{ NULL, NULL }
};

int auth_request_var_expand(string_t *dest, const char *str,
			    const struct auth_request *auth_request,
			    auth_request_escape_func_t *escape_func,
			    const char **error_r)
{
	return auth_request_var_expand_with_table(dest, str, auth_request,
		auth_request_get_var_expand_table(auth_request),
		escape_func, error_r);
}

int auth_request_var_expand_with_table(string_t *dest, const char *str,
				       const struct auth_request *auth_request,
				       const struct var_expand_table *table,
				       auth_request_escape_func_t *escape_func,
				       const char **error_r)
{
	struct auth_request_var_expand_ctx ctx;

	i_zero(&ctx);
	ctx.auth_request = auth_request;
	ctx.escape_func = escape_func == NULL ? escape_none : escape_func;
	const struct var_expand_params params = {
		.table = table,
		.providers = auth_request_var_expand_providers,
		.escape_func = (var_expand_escape_func_t *)ctx.escape_func,
		.context = &ctx,
		.escape_context = (void *)auth_request,
		.event = auth_request->event,
	};

	return var_expand(dest, str, &params, error_r);
}

int t_auth_request_var_expand(const char *str,
			      const struct auth_request *auth_request,
			      auth_request_escape_func_t *escape_func,
			      const char **value_r, const char **error_r)
{
	string_t *dest = t_str_new(128);
	int ret = auth_request_var_expand(dest, str, auth_request,
					  escape_func, error_r);
	*value_r = str_c(dest);
	return ret;
}

static void
auth_request_event_var_expand_callback(void *context,
				       struct var_expand_params *params_r)
{
	struct auth_request_var_expand_ctx *ctx = context;

	params_r->table = auth_request_get_var_expand_table(ctx->auth_request);
	params_r->providers = auth_request_var_expand_providers;
	params_r->context = ctx;
}

void auth_request_event_set_var_expand(struct auth_request *auth_request)
{
	struct auth_request_var_expand_ctx *ctx =
		p_new(auth_request->pool, struct auth_request_var_expand_ctx, 1);
	ctx->auth_request = auth_request;
	ctx->escape_func = escape_none;

	event_set_ptr(auth_request->event, SETTINGS_EVENT_VAR_EXPAND_CALLBACK,
		      auth_request_event_var_expand_callback);
	event_set_ptr(auth_request->event,
		      SETTINGS_EVENT_VAR_EXPAND_CALLBACK_CONTEXT, ctx);
}
