/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "auth-common.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "env-util.h"
#include "settings.h"
#include "oauth2.h"
#include "http-client.h"
#include "http-url.h"
#include "iostream-ssl.h"
#include "auth-request.h"
#include "auth-settings.h"
#include "passdb.h"
#include "llist.h"
#include "db-oauth2.h"
#include "dcrypt.h"
#include "dict.h"

#undef DEF
#define DEF(type, name) \
	SETTING_DEFINE_STRUCT_##type("oauth2_"#name, name, struct auth_oauth2_settings)

static const struct setting_define auth_oauth2_setting_defines[] = {
	DEF(STR, tokeninfo_url),
	DEF(STR, grant_url),
	DEF(STR, introspection_url),
	DEF(BOOLLIST, scope),
	DEF(ENUM, introspection_mode),
	DEF(STR_NOVARS, username_validation_format),
	DEF(STR, username_attribute),
	DEF(STR, active_attribute),
	DEF(STR, active_value),
	DEF(STR, client_id),
	DEF(STR, client_secret),
	DEF(BOOLLIST, issuers),
	DEF(STR, openid_configuration_url),
	DEF(BOOL, force_introspection),
	DEF(BOOL, send_auth_headers),
	DEF(BOOL, use_worker_with_mech),
	{ .type = SET_FILTER_NAME, .key = "oauth2_local_validation",
		.required_setting = "dict", },
	{ .type = SET_FILTER_NAME, .key = "oauth2", },
	SETTING_DEFINE_LIST_END
};

static const struct auth_oauth2_settings auth_oauth2_default_settings = {
	.tokeninfo_url = "",
	.grant_url = "",
	.introspection_url = "",
	.scope = ARRAY_INIT,
	.force_introspection = FALSE,
	.introspection_mode = ":auth:get:post:local",
	.username_validation_format = "%{user}",
	.username_attribute = "email",
	.active_attribute = "",
	.active_value = "",
	.client_id = "",
	.client_secret = "",
	.issuers = ARRAY_INIT,
	.openid_configuration_url = "",
	.send_auth_headers = FALSE,
	.use_worker_with_mech = FALSE,
};

/* <settings checks> */

static bool auth_oauth2_settings_check(struct event *event ATTR_UNUSED, void *_set,
				       pool_t pool ATTR_UNUSED, const char **error_r)
{
	const struct auth_oauth2_settings *set = _set;

	if (*set->introspection_mode == '\0') {
		if (*set->grant_url != '\0' ||
		    *set->tokeninfo_url != '\0' ||
		    *set->introspection_url != '\0') {
			*error_r = "Missing oauth2_introspection_mode";
			return FALSE;
		}
	} else if (strcmp(set->introspection_mode, "auth") == 0 ||
		 strcmp(set->introspection_mode, "get") == 0 ||
		 strcmp(set->introspection_mode, "post") == 0) {
		if (*set->tokeninfo_url == '\0' &&
		    *set->introspection_url == '\0') {
			*error_r = "Need at least one of oauth2_tokeninfo_url or oauth2_introspection_url";
			return FALSE;
		}
	}

	if (*set->grant_url != '\0' && *set->client_id == '\0') {
		*error_r = "oauth2_client_id is required with oauth2_grant_url";
		return FALSE;
	}

	if ((*set->client_id != '\0' && *set->client_secret == '\0') ||
	    (*set->client_id == '\0' && *set->client_secret != '\0')) {
		*error_r = "oauth2_client_id and oauth2_client_secret must be provided together";
		return FALSE;
	}

	if (*set->active_attribute == '\0' &&
	    *set->active_value != '\0') {
		*error_r = "Cannot have empty active_attribute if active_value is set";
		return FALSE;
	}

	return TRUE;
}

/* </settings checks> */

static const struct setting_keyvalue auth_oauth2_default_settings_keyvalue[] = {
	{ "oauth2/http_client_user_agent", "dovecot-oauth2-passdb/"DOVECOT_VERSION },
	{ "oauth2/http_client_max_idle_time", "60s" },
	{ "oauth2/http_client_max_parallel_connections", "10" },
	{ "oauth2/http_client_max_pipelined_requests", "1" },
	{ "oauth2/http_client_request_max_attempts", "1" },
	{ NULL, NULL }
};

const struct setting_parser_info auth_oauth2_setting_parser_info = {
	.name = "auth_oauth2",

	.defines = auth_oauth2_setting_defines,
	.defaults = &auth_oauth2_default_settings,
	.default_settings = auth_oauth2_default_settings_keyvalue,

	.struct_size = sizeof(struct auth_oauth2_settings),
	.pool_offset1 = 1 + offsetof(struct auth_oauth2_settings, pool),
	.ext_check_func = auth_oauth2_settings_check,
};

static const struct setting_define auth_oauth2_post_setting_defines[] = {
	{ .type = SET_STRLIST, .key = "oauth2_fields",
	  .offset = offsetof(struct auth_oauth2_post_settings, fields) },
};

static const struct auth_oauth2_post_settings auth_oauth2_post_default_settings = {
	.fields = ARRAY_INIT,
};

const struct setting_parser_info auth_oauth2_post_setting_parser_info = {
	.name = "auth_oauth2_fields",

	.defines = auth_oauth2_post_setting_defines,
	.defaults = &auth_oauth2_post_default_settings,

	.struct_size = sizeof(struct auth_oauth2_post_settings),
	.pool_offset1 = 1 + offsetof(struct auth_oauth2_post_settings, pool),
};

static struct event_category event_category_oauth2 = {
	.parent = &event_category_auth,
	.name = "oauth2",
};

struct db_oauth2 {
	struct db_oauth2 *prev,*next;

	pool_t pool;

	struct event *event;
	const struct auth_oauth2_settings *set;
	struct http_client *client;
	struct oauth2_settings oauth2_set;

	struct db_oauth2_request *head;
};

static struct db_oauth2 *db_oauth2_head = NULL;

static void db_oauth2_callback(struct db_oauth2_request *req,
			       enum passdb_result result,
			       const char *error_prefix, const char *error);
static void db_oauth2_free(struct db_oauth2 **_db);

static int db_oauth2_setup(struct db_oauth2 *db, const char **error_r)
{
	if (*db->set->introspection_mode == '\0') {
		*error_r = "Missing oauth2_introspection_mode setting";
		return -1;
	}

	if (http_client_init_auto(db->event, &db->client, error_r) < 0)
		return -1;

	i_zero(&db->oauth2_set);
	db->oauth2_set.client = db->client;
	db->oauth2_set.tokeninfo_url = db->set->tokeninfo_url,
	db->oauth2_set.grant_url = db->set->grant_url,
	db->oauth2_set.introspection_url = db->set->introspection_url;
	db->oauth2_set.client_id = db->set->client_id;
	db->oauth2_set.client_secret = db->set->client_secret;
	db->oauth2_set.send_auth_headers = db->set->send_auth_headers;
	if (!array_is_empty(&db->set->scope)) {
		db->oauth2_set.scope =
			p_array_const_string_join(db->pool, &db->set->scope, " ");
	} else
		db->oauth2_set.scope = "";
	if (!array_is_empty(&db->set->issuers)) {
		const char *elem;
		ARRAY_TYPE(const_string) dup;
		p_array_init(&dup, db->pool, array_count(&db->set->issuers));
		array_foreach_elem(&db->set->issuers, elem) {
			array_push_back(&dup, &elem);
		}
		array_append_space(&dup);
		db->oauth2_set.issuers = array_front(&dup);
	}

	if (strcmp(db->set->introspection_mode, "local") == 0) {
		struct event *event = event_create(db->event);
	        settings_event_add_filter_name(event, "oauth2_local_validation");
		int ret = dict_init_auto(event, &db->oauth2_set.key_dict, error_r);
		event_unref(&event);
		if (ret < 0)
			return ret;
	}

	if (*db->set->active_attribute == '\0' &&
	    *db->set->active_value != '\0') {
		*error_r = "oauth2: Cannot have empty active_attribute is active_value is set";
		return -1;
	}

	if (strcmp(db->set->introspection_mode, "auth") == 0) {
		db->oauth2_set.introspection_mode = INTROSPECTION_MODE_GET_AUTH;
	} else if (strcmp(db->set->introspection_mode, "get") == 0) {
		db->oauth2_set.introspection_mode = INTROSPECTION_MODE_GET;
	} else if (strcmp(db->set->introspection_mode, "post") == 0) {
		db->oauth2_set.introspection_mode = INTROSPECTION_MODE_POST;
	} else if (strcmp(db->set->introspection_mode, "local") == 0) {
		db->oauth2_set.introspection_mode = INTROSPECTION_MODE_LOCAL;
	} else {
		*error_r = t_strdup_printf("oauth2: Invalid value '%s' for introspection mode, must be on auth, get, post or local",
					   db->set->introspection_mode);
		return -1;
	}

	if (db->oauth2_set.introspection_mode == INTROSPECTION_MODE_LOCAL) {
		const char *error ATTR_UNUSED;
		/* failure to initialize dcrypt is not fatal - we can still
		   validate HMAC based keys */
		(void)dcrypt_initialize(NULL, NULL, &error);
		/* initialize key cache */
		db->oauth2_set.key_cache = oauth2_validation_key_cache_init();
	}

	if (*db->set->openid_configuration_url != '\0') {
		struct http_url *parsed_url ATTR_UNUSED;
		const char *error;
		if (http_url_parse(db->set->openid_configuration_url, NULL, 0,
				   pool_datastack_create(), &parsed_url,
				   &error) < 0) {
			*error_r = t_strdup_printf("Invalid openid_configuration_url: %s",
						   error);
			return -1;
		}
	}

	return 0;
}

int db_oauth2_init(struct event *event, bool use_grant_password, struct db_oauth2 **db_r,
		   const char **error_r)
{
	struct db_oauth2 *db;
	const struct auth_oauth2_settings *db_set;
	struct event *db_event = event_create(event);
	event_add_category(db_event, &event_category_oauth2);
	settings_event_add_filter_name(db_event, "oauth2");
	if (settings_get(db_event, &auth_oauth2_setting_parser_info, 0, &db_set,
			 error_r) < 0) {
		event_unref(&db_event);
		return -1;
	}

	for (db = db_oauth2_head; db != NULL; db = db->next) {
		/* Ensure we do not match a db with one that is using
		   grant password, as that does not work with mech oauth2. */
		if (settings_equal(&auth_oauth2_setting_parser_info, db->set,
				   db_set, NULL) &&
		    use_grant_password == db->oauth2_set.use_grant_password)
			break;
	}

	if (db != NULL) {
		settings_free(db_set);
		event_unref(&db_event);
		*db_r = db;
		return 0;
	}

	pool_t pool = pool_alloconly_create("db_oauth2", 128);
	db = p_new(pool, struct db_oauth2, 1);
	db->pool = pool;
	db->event = db_event;
	db->set = db_set;
	DLLIST_PREPEND(&db_oauth2_head, db);

	if (db_oauth2_setup(db, error_r) < 0) {
		db_oauth2_free(&db);
		return -1;
	}
	db->oauth2_set.use_grant_password = use_grant_password;

	*db_r = db;
	return 0;
}

static void db_oauth2_free(struct db_oauth2 **_db)
{
	struct db_oauth2 *ptr, *db = *_db;

	for(ptr = db_oauth2_head; ptr != NULL; ptr = ptr->next) {
		if (ptr == db) {
			DLLIST_REMOVE(&db_oauth2_head, ptr);
			break;
		}
	}

	i_assert(ptr != NULL && ptr == db);

	/* make sure all requests are aborted */
	while (db->head != NULL) {
		if (db->head->req != NULL)
			oauth2_request_abort(&db->head->req);
		else {
			struct db_oauth2_request *req = db->head;
			DLLIST_REMOVE(&db->head, req);
			db_oauth2_callback(req, PASSDB_RESULT_INTERNAL_FAILURE,
					   "", "aborted");
		}
	}
	if (db->client != NULL)
		http_client_deinit(&db->client);
	if (db->oauth2_set.key_dict != NULL)
		dict_deinit(&db->oauth2_set.key_dict);
	oauth2_validation_key_cache_deinit(&db->oauth2_set.key_cache);
	settings_free(db->set);
	event_unref(&db->event);
	pool_unref(&db->pool);
}

const char *db_oauth2_get_openid_configuration_url(const struct db_oauth2 *db)
{
	return db->set->openid_configuration_url;
}

static bool
db_oauth2_have_all_fields(struct db_oauth2_request *req)
{
	if (!auth_fields_exists(req->fields, req->db->set->username_attribute))
		return FALSE;
	if (*req->db->set->active_attribute != '\0' && !auth_fields_exists(req->fields, req->db->set->active_attribute))
		return FALSE;

	return TRUE;
}

static int db_oauth2_var_expand_func_oauth2(const char *field_name,
					    const char **value_r, void *context,
					    const char **error_r)
{
	struct db_oauth2_request *ctx = context;

	if (ctx->fields != NULL) {
		*value_r = auth_fields_find(ctx->fields, field_name);
		return 0;
	} else {
		*error_r = t_strdup_printf("Field '%s' not found", field_name);
		return -1;
	}
}

static bool
db_oauth2_add_extra_fields(struct db_oauth2_request *req, const char **error_r)
{
	const struct var_expand_provider func_table[] = {
		{ "oauth2", db_oauth2_var_expand_func_oauth2 },
		{ NULL, NULL }
	};
	const struct var_expand_provider *provider_arr[] = {
		func_table,
		NULL
	};
	struct var_expand_params params = {
		.table = auth_request_get_var_expand_table(req->auth_request),
		.providers_arr = provider_arr,
		.context = req,
	};
	struct auth_request *request = req->auth_request;
	const struct auth_oauth2_post_settings *set;
	struct event *event = event_create(req->auth_request->event);
	event_set_ptr(event, SETTINGS_EVENT_VAR_EXPAND_PARAMS, &params);
	if (settings_get(event, &auth_oauth2_post_setting_parser_info, 0, &set, error_r) < 0) {
		event_unref(&event);
		return FALSE;
	}
	if (!array_is_empty(&set->fields)) {
		unsigned int n;
		const char *const *fields = array_get(&set->fields, &n);
		i_assert(n % 2 == 0);

		for (unsigned int i = 0; i < n; i += 2)
			auth_request_set_field(request, fields[i], fields[i + 1], NULL);
	}
	settings_free(set);
	event_unref(&event);
	return TRUE;
}

static void db_oauth2_fields_merge(struct db_oauth2_request *req,
				   ARRAY_TYPE(oauth2_field) *fields)
{
	const struct oauth2_field *field;

	if (req->fields == NULL)
		req->fields = auth_fields_init(req->pool);

	array_foreach(fields, field) {
		e_debug(authdb_event(req->auth_request),
			"Processing field %s",
			field->name);
		auth_fields_add(req->fields, field->name, field->value, 0);
	}
}

static const char *
db_oauth2_field_find(const ARRAY_TYPE(oauth2_field) *fields, const char *name)
{
	const struct oauth2_field *f;

	array_foreach(fields, f) {
		if (strcmp(f->name, name) == 0)
			return f->value;
	}
	return NULL;
}

static void db_oauth2_callback(struct db_oauth2_request *req,
			       enum passdb_result result,
			       const char *error_prefix, const char *error)
{
	db_oauth2_lookup_callback_t *callback = req->callback;
	req->callback = NULL;

	i_assert(result == PASSDB_RESULT_OK || error != NULL);

	/* Successful lookups were logged by the caller. Failed lookups will be
	   logged either with e_error() or e_info() by the callback. */
	if (callback != NULL) {
		DLLIST_REMOVE(&req->db->head, req);
		if (result != PASSDB_RESULT_OK)
			error = t_strconcat(error_prefix, error, NULL);
		callback(req, result, error, req->context);
	}
}

static bool
db_oauth2_validate_username(struct db_oauth2_request *req,
			    enum passdb_result *result_r, const char **error_r)
{
	const char *error;
	struct var_expand_table table[] = {
		{ .key = "user", .value = NULL },
		{ .key = "username", .value = NULL },
		{ .key = "domain", .value = NULL },
		VAR_EXPAND_TABLE_END
	};
	const char *username_value =
		auth_fields_find(req->fields, req->db->set->username_attribute);

	if (username_value == NULL) {
		*result_r = PASSDB_RESULT_INTERNAL_FAILURE;
		*error_r = "No username returned";
		return FALSE;
	}

	table[0].value = username_value;
	table[1].value = t_strcut(username_value, '@');
	table[2].value = i_strchr_to_next(username_value, '@');

	string_t *username_val = t_str_new(strlen(username_value));

	const struct var_expand_params params = {
		.table = table,
		.event = req->auth_request->event,
	};

	if (var_expand(username_val, req->db->set->username_validation_format,
		       &params, &error) < 0) {
		*error_r = t_strdup_printf("var_expand(%s) failed: %s",
					req->db->set->username_validation_format, error);
		*result_r = PASSDB_RESULT_INTERNAL_FAILURE;
		return FALSE;
	} else if (strcmp(req->auth_request->fields.user, str_c(username_val)) != 0) {
		*error_r = t_strdup_printf("Username '%s' did not match '%s'",
					   req->auth_request->fields.user, str_c(username_val));
		*result_r = PASSDB_RESULT_USER_UNKNOWN;
		return FALSE;
	} else {
		req->username = p_strdup(req->pool, str_c(username_val));
		return TRUE;
	}
}

static bool
db_oauth2_user_is_enabled(struct db_oauth2_request *req,
			  enum passdb_result *result_r, const char **error_r)
{
	if (*req->db->set->active_attribute == '\0' ) {
		e_debug(authdb_event(req->auth_request),
			"oauth2 active_attribute is not configured; skipping the check");
	    	return TRUE;
	}

	const char *active_value =
		auth_fields_find(req->fields, req->db->set->active_attribute);

	if (active_value == NULL) {
		e_debug(authdb_event(req->auth_request),
			"oauth2 active_attribute \"%s\" is not present in the oauth2 server's response",
			req->db->set->active_attribute);
		*error_r = "Missing active_attribute from token";
		*result_r = PASSDB_RESULT_PASSWORD_MISMATCH;
		return FALSE;
	}

	if (*req->db->set->active_value == '\0') {
		e_debug(authdb_event(req->auth_request),
			"oauth2 active_attribute \"%s\" present; skipping the check on value",
			req->db->set->active_attribute);
	    	return TRUE;
	}

	if (strcmp(req->db->set->active_value, active_value) != 0) {
		e_debug(authdb_event(req->auth_request),
			"oauth2 active_attribute check failed: expected %s=\"%s\" but got \"%s\"",
			req->db->set->active_attribute,
			req->db->set->active_value,
			active_value);
		*error_r = "Provided token is not valid";
		*result_r = PASSDB_RESULT_PASSWORD_MISMATCH;
		return FALSE;
	}

	e_debug(authdb_event(req->auth_request),
		"oauth2 active_attribute check succeeded");
	return TRUE;
}

static bool
db_oauth2_token_in_scope(struct db_oauth2_request *req,
			 enum passdb_result *result_r, const char **error_r)
{
	bool found = TRUE;
	if (!array_is_empty(&req->db->set->scope)) {
		found = FALSE;
		const char *value = auth_fields_find(req->fields, "scope");
		bool has_scope = value != NULL;
		if (!has_scope)
			value = auth_fields_find(req->fields, "aud");
		e_debug(authdb_event(req->auth_request),
			"Token scope(s): %s",
			value);
		if (value != NULL) {
			const char *wanted_scope;
			const char *const *entries = has_scope ?
				t_strsplit_spaces(value, " ") :
				t_strsplit_tabescaped(value);
			array_foreach_elem(&req->db->set->scope, wanted_scope) {
				if ((found = str_array_find(entries, wanted_scope)))
					break;
			}
		}
		if (!found) {
			*error_r = t_strdup_printf("Token is not valid for scope '%s'",
						   req->db->oauth2_set.scope);
			*result_r = PASSDB_RESULT_USER_DISABLED;
		}
	}
	return found;
}

static void db_oauth2_process_fields(struct db_oauth2_request *req,
				     enum passdb_result *result_r,
				     const char **error_r)
{
	*error_r = NULL;

	if (db_oauth2_user_is_enabled(req, result_r, error_r) &&
	    db_oauth2_validate_username(req, result_r, error_r) &&
	    db_oauth2_token_in_scope(req, result_r, error_r)) {
		/* The user has now been successfully authenticated,
		   mark the request as such. This allows having no
		   passdb in config. */
		req->auth_request->passdb_success = TRUE;
		*result_r = PASSDB_RESULT_OK;
		auth_fields_snapshot(req->auth_request->fields.extra_fields);
		if (!db_oauth2_add_extra_fields(req, error_r)) {
			auth_fields_rollback(req->auth_request->fields.extra_fields);
			req->auth_request->passdb_success = FALSE;
			*result_r = PASSDB_RESULT_INTERNAL_FAILURE;
		}
	} else {
		i_assert(*result_r != PASSDB_RESULT_OK && *error_r != NULL);
	}
}

static void
db_oauth2_introspect_continue(struct oauth2_request_result *result,
			      struct db_oauth2_request *req)
{
	enum passdb_result passdb_result;
	const char *error;

	req->req = NULL;

	if (result->error != NULL) {
		/* fail here */
		passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;
		error = result->error;
	} else {
		e_debug(authdb_event(req->auth_request),
			"Introspection succeeded");
		db_oauth2_fields_merge(req, result->fields);
		db_oauth2_process_fields(req, &passdb_result, &error);
	}
	db_oauth2_callback(req, passdb_result, "Introspection failed: ", error);
}

static void db_oauth2_lookup_introspect(struct db_oauth2_request *req)
{
	struct oauth2_request_input input;
	i_zero(&input);

	e_debug(authdb_event(req->auth_request),
		"Making introspection request to %s",
		req->db->set->introspection_url);
	input.token = req->token;
	input.local_ip = req->auth_request->fields.local_ip;
	input.local_port = req->auth_request->fields.local_port;
	input.remote_ip = req->auth_request->fields.remote_ip;
	input.remote_port = req->auth_request->fields.remote_port;
	input.real_local_ip = req->auth_request->fields.real_local_ip;
	input.real_local_port = req->auth_request->fields.real_local_port;
	input.real_remote_ip = req->auth_request->fields.real_remote_ip;
	input.real_remote_port = req->auth_request->fields.real_remote_port;
	input.protocol = req->auth_request->fields.protocol;

	req->req = oauth2_introspection_start(&req->db->oauth2_set, &input,
					      db_oauth2_introspect_continue, req);
}

static void db_oauth2_local_validation(struct db_oauth2_request *req,
				       const char *token)
{
	bool is_jwt ATTR_UNUSED;
	const char *error = NULL;
	enum passdb_result passdb_result;
	ARRAY_TYPE(oauth2_field) fields;
	t_array_init(&fields, 8);
	if (oauth2_try_parse_jwt(&req->db->oauth2_set, token,
				 &fields, &is_jwt, &error) < 0) {
		passdb_result = PASSDB_RESULT_PASSWORD_MISMATCH;
	} else {
		db_oauth2_fields_merge(req, &fields);
		db_oauth2_process_fields(req, &passdb_result, &error);
	}
	if (passdb_result == PASSDB_RESULT_OK) {
		e_debug(authdb_event(req->auth_request),
			"Local validation succeeded");
	}
	db_oauth2_callback(req, passdb_result,
			   "Local validation failed: ", error);
}

static void
db_oauth2_lookup_continue_valid(struct db_oauth2_request *req,
				ARRAY_TYPE(oauth2_field) *fields,
				const char *error_prefix)
{
	enum passdb_result passdb_result;
	const char *error;

	db_oauth2_fields_merge(req, fields);
	if (db_oauth2_have_all_fields(req) &&
	    !req->db->set->force_introspection) {
		/* pass */
	} else if (req->db->oauth2_set.introspection_mode ==
		   INTROSPECTION_MODE_LOCAL) {
		e_debug(authdb_event(req->auth_request),
			"Attempting to locally validate token");
		db_oauth2_local_validation(req, req->token);
		return;
	} else if (!db_oauth2_user_is_enabled(req, &passdb_result, &error)) {
		db_oauth2_callback(req, passdb_result,
				   "Token is not valid: ", error);
		return;
	} else if (*req->db->set->introspection_url != '\0') {
		db_oauth2_lookup_introspect(req);
		return;
	}
	db_oauth2_process_fields(req, &passdb_result, &error);
	db_oauth2_callback(req, passdb_result, error_prefix, error);
}

static void
db_oauth2_lookup_continue(struct oauth2_request_result *result,
			  struct db_oauth2_request *req)
{
	i_assert(req->token != NULL);
	req->req = NULL;

	if (result->error != NULL) {
		db_oauth2_callback(req, PASSDB_RESULT_INTERNAL_FAILURE,
				   "Token validation failed: ", result->error);
	} else if (!result->valid) {
		db_oauth2_callback(req, PASSDB_RESULT_PASSWORD_MISMATCH,
				   "Token validation failed: ",
				   "Invalid token");
	} else {
		e_debug(authdb_event(req->auth_request),
			"Token validation succeeded");
		db_oauth2_lookup_continue_valid(req, result->fields,
						"Token validation failed: ");
	}
}

static void
db_oauth2_lookup_passwd_grant(struct oauth2_request_result *result,
			      struct db_oauth2_request *req)
{
	enum passdb_result passdb_result;
	const char *token, *error;

	i_assert(req->token == NULL);
	req->req = NULL;

	if (result->valid) {
		e_debug(authdb_event(req->auth_request),
			"Password grant succeeded");
		token = db_oauth2_field_find(result->fields, "access_token");
		if (token == NULL) {
			db_oauth2_callback(req, PASSDB_RESULT_INTERNAL_FAILURE,
					   "Password grant failed: ",
					   "OAuth2 token missing from reply");
		} else {
			req->token = p_strdup(req->pool, token);
			db_oauth2_lookup_continue_valid(req, result->fields,
				"Password grant failed: ");
		}
		return;
	}

	passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;
	if (result->error != NULL)
		error = result->error;
	else {
		passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;
		error = db_oauth2_field_find(result->fields, "error");
		if (error == NULL)
			error = "OAuth2 server returned failure without error field";
		else if (strcmp("invalid_grant", error) == 0)
			passdb_result = PASSDB_RESULT_PASSWORD_MISMATCH;
	}
	db_oauth2_callback(req, passdb_result,
			   "Password grant failed: ", error);
}

#undef db_oauth2_lookup
void db_oauth2_lookup(struct db_oauth2 *db, struct db_oauth2_request *req,
		      const char *token, struct auth_request *request,
		      db_oauth2_lookup_callback_t *callback, void *context)
{
	struct oauth2_request_input input;
	i_zero(&input);

	req->db = db;
	req->token = p_strdup(req->pool, token);
	req->callback = callback;
	req->context = context;
	req->auth_request = request;

	input.token = token;
	input.local_ip = req->auth_request->fields.local_ip;
	input.local_port = req->auth_request->fields.local_port;
	input.remote_ip = req->auth_request->fields.remote_ip;
	input.remote_port = req->auth_request->fields.remote_port;
	input.real_local_ip = req->auth_request->fields.real_local_ip;
	input.real_local_port = req->auth_request->fields.real_local_port;
	input.real_remote_ip = req->auth_request->fields.real_remote_ip;
	input.real_remote_port = req->auth_request->fields.real_remote_port;
	input.protocol = req->auth_request->fields.protocol;

	if (db->oauth2_set.introspection_mode == INTROSPECTION_MODE_LOCAL &&
	    !db->oauth2_set.use_grant_password) {
		/* try to validate token locally */
		e_debug(authdb_event(req->auth_request),
			"Attempting to locally validate token");
		db_oauth2_local_validation(req, token);
		return;

	}
	if (db->oauth2_set.use_grant_password) {
		e_debug(authdb_event(req->auth_request),
			"Making grant url request to %s",
			db->set->grant_url);
		/* There is no valid token until grant looks it up. */
		req->token = NULL;
		req->req = oauth2_passwd_grant_start(&db->oauth2_set, &input,
						     request->fields.user, request->mech_password,
						     db_oauth2_lookup_passwd_grant, req);
	} else if (*db->oauth2_set.tokeninfo_url == '\0') {
		e_debug(authdb_event(req->auth_request),
			"Making introspection request to %s",
			db->set->introspection_url);
		req->req = oauth2_introspection_start(&req->db->oauth2_set, &input,
						      db_oauth2_introspect_continue, req);
	} else {
		e_debug(authdb_event(req->auth_request),
			"Making token validation lookup to %s",
			db->oauth2_set.tokeninfo_url);
		req->req = oauth2_token_validation_start(&db->oauth2_set, &input,
							 db_oauth2_lookup_continue, req);
	}
	i_assert(req->req != NULL);
	DLLIST_PREPEND(&db->head, req);
}

bool db_oauth2_use_worker(const struct db_oauth2 *db)
{
	return db->set->use_worker_with_mech;
}

void db_oauth2_deinit(void)
{
	while (db_oauth2_head != NULL) {
		struct db_oauth2 *db = db_oauth2_head;
		db_oauth2_free(&db);
	}
}
