/* Copyright (c) 2017-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "var-expand.h"
#include "env-util.h"
#include "var-expand.h"
#include "settings.h"
#include "oauth2.h"
#include "http-client.h"
#include "iostream-ssl.h"
#include "auth-request.h"
#include "auth-settings.h"
#include "passdb.h"
#include "passdb-template.h"
#include "llist.h"
#include "db-oauth2.h"
#include "dcrypt.h"
#include "dict.h"

#include <stddef.h>

struct passdb_oauth2_settings {
	/* tokeninfo endpoint, format https://endpoint/somewhere?token= */
	const char *tokeninfo_url;
	/* password grant endpoint, format https://endpoint/somewhere */
	const char *grant_url;
	/* introspection endpoint, format https://endpoint/somewhere */
	const char *introspection_url;
	/* expected scope, optional */
	const char *scope;
	/* mode of introspection, one of get, get-auth, post
	   - get: append token to url
	   - get-auth: send token with header Authorization: Bearer token
	   - post: send token=<token> as POST request
	*/
	const char *introspection_mode;
	/* normalization var-expand template for username, defaults to %Lu */
	const char *username_format;
	/* name of username attribute to lookup, mandatory */
	const char *username_attribute;
	/* name of account is active attribute, optional */
	const char *active_attribute;
	/* expected active value for active attribute, optional */
	const char *active_value;
	/* client identificator for oauth2 server */
	const char *client_id;
	/* not really used, but have to present by oauth2 specs */
	const char *client_secret;
	/* template to expand into passdb */
	const char *pass_attrs;
	/* template to expand into key path, turns on local validation support */
	const char *local_validation_key_dict;

	/* TLS options */
	const char *tls_ca_cert_file;
	const char *tls_ca_cert_dir;
	const char *tls_cert_file;
	const char *tls_key_file;
	const char *tls_cipher_suite;

	/* HTTP rawlog directory */
	const char *rawlog_dir;

	/* HTTP client options */
	unsigned int timeout_msecs;
	unsigned int max_idle_time_msecs;
	unsigned int max_parallel_connections;
	unsigned int max_pipelined_requests;
	bool tls_allow_invalid_cert;

	bool debug;
	/* Should introspection be done even if not necessary */
	bool force_introspection;
	/* Should we send service and local/remote endpoints as X-Dovecot-Auth headers */
	bool send_auth_headers;
	bool use_grant_password;
};

struct db_oauth2 {
	struct db_oauth2 *prev,*next;

	pool_t pool;

	const char *config_path;
	struct passdb_oauth2_settings set;
	struct http_client *client;
	struct passdb_template *tmpl;
	struct oauth2_settings oauth2_set;

	struct db_oauth2_request *head;

	unsigned int refcount;
};

static struct db_oauth2 *db_oauth2_head = NULL;

#undef DEF_STR
#undef DEF_BOOL
#undef DEF_INT

#define DEF_STR(name) DEF_STRUCT_STR(name, passdb_oauth2_settings)
#define DEF_BOOL(name) DEF_STRUCT_BOOL(name, passdb_oauth2_settings)
#define DEF_INT(name) DEF_STRUCT_INT(name, passdb_oauth2_settings)

static struct setting_def setting_defs[] = {
	DEF_STR(tokeninfo_url),
	DEF_STR(grant_url),
	DEF_STR(introspection_url),
	DEF_STR(scope),
	DEF_BOOL(force_introspection),
	DEF_STR(introspection_mode),
	DEF_STR(username_format),
	DEF_STR(username_attribute),
	DEF_STR(pass_attrs),
	DEF_STR(local_validation_key_dict),
	DEF_STR(active_attribute),
	DEF_STR(active_value),
	DEF_STR(client_id),
	DEF_STR(client_secret),
	DEF_INT(timeout_msecs),
	DEF_INT(max_idle_time_msecs),
	DEF_INT(max_parallel_connections),
	DEF_INT(max_pipelined_requests),
	DEF_BOOL(send_auth_headers),
	DEF_BOOL(use_grant_password),

	DEF_STR(tls_ca_cert_file),
	DEF_STR(tls_ca_cert_dir),
	DEF_STR(tls_cert_file),
	DEF_STR(tls_key_file),
	DEF_STR(tls_cipher_suite),
	DEF_BOOL(tls_allow_invalid_cert),

	DEF_STR(rawlog_dir),

	DEF_BOOL(debug),

	{ 0, NULL, 0 }
};

static struct passdb_oauth2_settings default_oauth2_settings = {
	.tokeninfo_url = "",
	.grant_url = "",
	.introspection_url = "",
	.scope = "",
	.force_introspection = FALSE,
	.introspection_mode = "",
	.username_format = "%Lu",
	.username_attribute = "email",
	.active_attribute = "",
	.active_value = "",
	.client_id = "",
	.client_secret = "",
	.pass_attrs = "",
	.local_validation_key_dict = "",
	.rawlog_dir = "",
	.timeout_msecs = 0,
	.max_idle_time_msecs = 60000,
	.max_parallel_connections = 1,
	.max_pipelined_requests = 1,
	.tls_ca_cert_file = NULL,
	.tls_ca_cert_dir = NULL,
	.tls_cert_file = NULL,
	.tls_key_file = NULL,
	.tls_cipher_suite = "HIGH:!SSLv2",
	.tls_allow_invalid_cert = FALSE,
	.send_auth_headers = FALSE,
	.use_grant_password = FALSE,
	.debug = FALSE,
};

static const char *parse_setting(const char *key, const char *value,
				 struct db_oauth2 *db)
{
	return parse_setting_from_defs(db->pool, setting_defs,
				       &db->set, key, value);
}

struct db_oauth2 *db_oauth2_init(const char *config_path)
{
	struct db_oauth2 *db;
	const char *error;
	struct ssl_iostream_settings ssl_set;
	struct http_client_settings http_set;

	for(db = db_oauth2_head; db != NULL; db = db->next) {
		if (strcmp(db->config_path, config_path) == 0) {
			db->refcount++;
			return db;
		}
	}

	pool_t pool = pool_alloconly_create("db_oauth2", 128);
	db = p_new(pool, struct db_oauth2, 1);
	db->pool = pool;
	db->refcount = 1;
	db->config_path = p_strdup(pool, config_path);
	db->set = default_oauth2_settings;

	if (!settings_read_nosection(config_path, parse_setting, db, &error))
		i_fatal("oauth2 %s: %s", config_path, error);

	db->tmpl = passdb_template_build(pool, db->set.pass_attrs);

	i_zero(&ssl_set);
	i_zero(&http_set);

	ssl_set.cipher_list = db->set.tls_cipher_suite;
	ssl_set.ca_file = db->set.tls_ca_cert_file;
	ssl_set.ca_dir = db->set.tls_ca_cert_dir;
	if (db->set.tls_cert_file != NULL && *db->set.tls_cert_file != '\0') {
		ssl_set.cert.cert = db->set.tls_cert_file;
		ssl_set.cert.key = db->set.tls_key_file;
	}
	ssl_set.prefer_server_ciphers = TRUE;
	ssl_set.allow_invalid_cert = db->set.tls_allow_invalid_cert;
	ssl_set.verbose = db->set.debug;
	ssl_set.verbose_invalid_cert = db->set.debug;
	http_set.ssl = &ssl_set;

	http_set.dns_client_socket_path = "dns-client";
	http_set.user_agent = "dovecot-oauth2-passdb/" DOVECOT_VERSION;

	if (*db->set.local_validation_key_dict == '\0' &&
	    *db->set.tokeninfo_url == '\0' &&
	    (*db->set.grant_url == '\0' || *db->set.client_id == '\0') &&
	    *db->set.introspection_url == '\0')
		i_fatal("oauth2: Password grant, tokeninfo, introspection URL or "
			"validation key dictionary must be given");

	if (*db->set.rawlog_dir != '\0')
		http_set.rawlog_dir = db->set.rawlog_dir;

	http_set.max_idle_time_msecs = db->set.max_idle_time_msecs;
	http_set.max_parallel_connections = db->set.max_parallel_connections;
	http_set.max_pipelined_requests = db->set.max_pipelined_requests;
	http_set.no_auto_redirect = FALSE;
	http_set.no_auto_retry = TRUE;
	http_set.debug = db->set.debug;

	db->client = http_client_init(&http_set);

	i_zero(&db->oauth2_set);
	db->oauth2_set.client = db->client;
	db->oauth2_set.tokeninfo_url = db->set.tokeninfo_url,
	db->oauth2_set.grant_url = db->set.grant_url,
	db->oauth2_set.introspection_url = db->set.introspection_url;
	db->oauth2_set.client_id = db->set.client_id;
	db->oauth2_set.client_secret = db->set.client_secret;
	db->oauth2_set.timeout_msecs = db->set.timeout_msecs;
	db->oauth2_set.send_auth_headers = db->set.send_auth_headers;
	db->oauth2_set.use_grant_password = db->set.use_grant_password;
	db->oauth2_set.scope = db->set.scope;

	if (*db->set.introspection_mode == '\0' ||
	    strcmp(db->set.introspection_mode, "auth") == 0) {
		db->oauth2_set.introspection_mode = INTROSPECTION_MODE_GET_AUTH;
	} else if (strcmp(db->set.introspection_mode, "get") == 0) {
		db->oauth2_set.introspection_mode = INTROSPECTION_MODE_GET;
	} else if (strcmp(db->set.introspection_mode, "post") == 0) {
		db->oauth2_set.introspection_mode = INTROSPECTION_MODE_POST;
	} else {
		i_fatal("Invalid value '%s' for introspection mode, must be on auth, get or post",
			db->set.introspection_mode);
	}

	if (*db->set.local_validation_key_dict != '\0') {
		struct dict_settings dict_set = {
			.username = "",
			.base_dir = global_auth_settings->base_dir,
			.value_type = DICT_DATA_TYPE_STRING,
		};
		if (dict_init(db->set.local_validation_key_dict, &dict_set,
			      &db->oauth2_set.key_dict, &error) < 0)
			i_fatal("Cannot initialize key dict: %s", error);
		/* failure to initialize dcrypt is not fatal - we can still
		   validate HMAC based keys */
		(void)dcrypt_initialize(NULL, NULL, NULL);
		/* initialize key cache */
		db->oauth2_set.key_cache = oauth2_validation_key_cache_init();
	}

	DLLIST_PREPEND(&db_oauth2_head, db);

	return db;
}

void db_oauth2_ref(struct db_oauth2 *db)
{
	i_assert(db->refcount > 0);
	db->refcount++;
}

void db_oauth2_unref(struct db_oauth2 **_db)
{
	struct db_oauth2 *ptr, *db = *_db;
	i_assert(db->refcount > 0);

	if (--db->refcount > 0) return;

	for(ptr = db_oauth2_head; ptr != NULL; ptr = ptr->next) {
		if (ptr == db) {
			DLLIST_REMOVE(&db_oauth2_head, ptr);
			break;
		}
	}

	i_assert(ptr != NULL && ptr == db);

	/* make sure all requests are aborted */
	while (db->head != NULL)
		oauth2_request_abort(&db->head->req);

	http_client_deinit(&db->client);
	if (db->oauth2_set.key_dict != NULL)
		dict_deinit(&db->oauth2_set.key_dict);
	oauth2_validation_key_cache_deinit(&db->oauth2_set.key_cache);
	pool_unref(&db->pool);
}

static bool
db_oauth2_have_all_fields(struct db_oauth2_request *req)
{
	unsigned int n,i;
	unsigned int size,idx;
	const char *const *args = passdb_template_get_args(req->db->tmpl, &n);

	if (req->fields == NULL)
		return FALSE;

	for(i=1;i<n;i+=2) {
		const char *ptr = args[i];
		while(ptr != NULL) {
			ptr = strchr(ptr, '%');
			if (ptr != NULL) {
				const char *field;
				ptr++;
				var_get_key_range(ptr, &idx, &size);
				ptr = ptr+idx;
				field = t_strndup(ptr,size);
				if (str_begins(field, "oauth2:") &&
				    !auth_fields_exists(req->fields, ptr+8))
					return FALSE;
				ptr = ptr+size;
			}
		}
	}

	if (!auth_fields_exists(req->fields, req->db->set.username_attribute))
		return FALSE;
	if (*req->db->set.active_attribute != '\0' && !auth_fields_exists(req->fields, req->db->set.active_attribute))
		return FALSE;

	return TRUE;
}

static const char *field_get_default(const char *data)
{
	const char *p;

	p = strchr(data, ':');
	if (p == NULL)
		return "";
	else {
		/* default value given */
		return p+1;
	}
}

static int db_oauth2_var_expand_func_oauth2(const char *data, void *context,
					    const char **value_r,
					    const char **error_r ATTR_UNUSED)
{
	struct db_oauth2_request *ctx = context;
	const char *field_name = t_strcut(data, ':');
	const char *value = NULL;

	if (ctx->fields != NULL)
		value = auth_fields_find(ctx->fields, field_name);
	*value_r = value != NULL ? value : field_get_default(data);

	return 1;
}

static const char *escape_none(const char *value, const struct auth_request *req ATTR_UNUSED)
{
	return value;
}

static const struct var_expand_table *
db_oauth2_value_get_var_expand_table(struct auth_request *auth_request,
				     const char *oauth2_value)
{
	struct var_expand_table *table;
	unsigned int count = 1;

	table = auth_request_get_var_expand_table_full(auth_request, NULL,
						       &count);
	table[0].key = '$';
	table[0].value = oauth2_value;
	return table;
}

static bool
db_oauth2_template_export(struct db_oauth2_request *req,
			  enum passdb_result *result_r, const char **error_r)
{
	/* var=$ expands into var=${oauth2:var} */
	const struct var_expand_func_table funcs_table[] = {
		{ "oauth2", db_oauth2_var_expand_func_oauth2 },
		{ NULL, NULL }
	};
	string_t *dest;
	const char *const *args, *value;
	struct passdb_template *tmpl = req->db->tmpl;
	unsigned int i, count;

	if (passdb_template_is_empty(tmpl))
		return TRUE;

	dest = t_str_new(256);
	args = passdb_template_get_args(tmpl, &count);
	i_assert((count % 2) == 0);
	for (i = 0; i < count; i += 2) {
		if (args[i+1] == NULL)
			value = "";
		else {
			str_truncate(dest, 0);
			const struct var_expand_table *
				table = db_oauth2_value_get_var_expand_table(req->auth_request,
									     auth_fields_find(req->fields, args[i]));
			if (var_expand_with_funcs(dest, args[i+1], table, funcs_table,
						  req, error_r) < 0) {
				*result_r = PASSDB_RESULT_INTERNAL_FAILURE;
				return FALSE;
			}
			value = str_c(dest);
		}

		auth_request_set_field(req->auth_request, args[i], value,
				       STATIC_PASS_SCHEME);
	}
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
			"oauth2: Processing field %s",
			field->name);
		auth_fields_add(req->fields, field->name, field->value, 0);
	}
}

static void db_oauth2_callback(struct db_oauth2_request *req,
			       enum passdb_result result,
			       const char *error)
{
	db_oauth2_lookup_callback_t *callback = req->callback;
	req->callback = NULL;

	i_assert(result == PASSDB_RESULT_OK || error != NULL);

	e_debug(authdb_event(req->auth_request),
		"oauth2: callback(result: %s, error: %s)",
		passdb_result_to_string(result), error);

	if (callback != NULL) {
		DLLIST_REMOVE(&req->db->head, req);
		callback(req, result, error, req->context);
	}
}

static bool
db_oauth2_validate_username(struct db_oauth2_request *req,
			    enum passdb_result *result_r, const char **error_r)
{
	const char *error;
	struct var_expand_table table[] = {
		{ 'u', NULL, "user" },
		{ 'n', NULL, "username" },
		{ 'd', NULL, "domain" },
		{ '\0', NULL, NULL }
	};
	const char *username_value =
		auth_fields_find(req->fields, req->db->set.username_attribute);

	if (username_value == NULL) {
		*result_r = PASSDB_RESULT_INTERNAL_FAILURE;
		*error_r = "No username returned";
		return FALSE;
	}

	table[0].value = username_value;
	table[1].value = t_strcut(username_value, '@');
	table[2].value = i_strchr_to_next(username_value, '@');

	string_t *username_req = t_str_new(32);
	string_t *username_val = t_str_new(strlen(username_value));

	if (auth_request_var_expand(username_req, req->db->set.username_format, req->auth_request, escape_none, &error) < 0 ||
	    var_expand(username_val, req->db->set.username_format, table, &error) < 0) {
		*error_r = t_strdup_printf("var_expand(%s) failed: %s",
					req->db->set.username_format, error);
		*result_r = PASSDB_RESULT_INTERNAL_FAILURE;
		return FALSE;
	} else if (!str_equals(username_req, username_val)) {
		*error_r = t_strdup_printf("Username '%s' did not match '%s'",
					str_c(username_req), str_c(username_val));
		*result_r = PASSDB_RESULT_USER_UNKNOWN;
		return FALSE;
	} else {
		return TRUE;
	}
}

static bool
db_oauth2_user_is_enabled(struct db_oauth2_request *req,
			  enum passdb_result *result_r, const char **error_r)
{
	if (*req->db->set.active_attribute != '\0') {
		const char *active_value = auth_fields_find(req->fields, req->db->set.active_attribute);
		if (active_value == NULL ||
		    (*req->db->set.active_value != '\0' &&
		     strcmp(req->db->set.active_value, active_value) != 0)) {
			*error_r = "User account is not active";
			*result_r = PASSDB_RESULT_USER_DISABLED;
			return FALSE;
		}
	}
	return TRUE;
}

static bool
db_oauth2_token_in_scope(struct db_oauth2_request *req,
			 enum passdb_result *result_r, const char **error_r)
{
	if (*req->db->set.scope != '\0') {
		bool found = FALSE;
		const char *value = auth_fields_find(req->fields, "scope");
		if (value == NULL)
			value = auth_fields_find(req->fields, "aud");
		e_debug(authdb_event(req->auth_request),
			"oauth2: Token scope(s): %s",
			value);
		if (value != NULL) {
			const char **wanted_scopes =
				t_strsplit_spaces(req->db->set.scope, " ");
			const char **scopes = t_strsplit_spaces(value, " ");
			for (; !found && *wanted_scopes != NULL; wanted_scopes++)
				found = str_array_find(scopes, *wanted_scopes);
		}
		if (!found) {
			*error_r = t_strdup_printf("Token is not valid for scope '%s'",
						   req->db->set.scope);
			*result_r = PASSDB_RESULT_USER_DISABLED;
			return FALSE;
		}
	}
	return TRUE;
}

static void db_oauth2_process_fields(struct db_oauth2_request *req,
				     enum passdb_result *result_r,
				     const char **error_r)
{
	*error_r = NULL;

	if (db_oauth2_validate_username(req, result_r, error_r) &&
	    db_oauth2_user_is_enabled(req, result_r, error_r) &&
	    db_oauth2_token_in_scope(req, result_r, error_r) &&
	    db_oauth2_template_export(req, result_r, error_r)) {
		*result_r = PASSDB_RESULT_OK;
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

	e_debug(authdb_event(req->auth_request),
		"oauth2: Introspection result: %s",
		result->success ? "success" : "failed");

	if (!result->success) {
		/* fail here */
		passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;
		error = result->error;
	} else {
		db_oauth2_fields_merge(req, result->fields);
		db_oauth2_process_fields(req, &passdb_result, &error);
	}
	db_oauth2_callback(req, passdb_result, error);
}

static void db_oauth2_lookup_introspect(struct db_oauth2_request *req)
{
	struct oauth2_request_input input;
	i_zero(&input);

	e_debug(authdb_event(req->auth_request),
		"oauth2: Making introspection request to %s",
		req->db->set.introspection_url);
	input.token = req->token;
	input.local_ip = req->auth_request->local_ip;
	input.local_port = req->auth_request->local_port;
	input.remote_ip = req->auth_request->remote_ip;
	input.remote_port = req->auth_request->remote_port;
	input.real_local_ip = req->auth_request->real_local_ip;
	input.real_local_port = req->auth_request->real_local_port;
	input.real_remote_ip = req->auth_request->real_remote_ip;
	input.real_remote_port = req->auth_request->real_remote_port;
	input.service = req->auth_request->service;

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
	db_oauth2_callback(req, passdb_result, error);
}

static void
db_oauth2_lookup_continue(struct oauth2_request_result *result,
			  struct db_oauth2_request *req)
{
	enum passdb_result passdb_result;
	const char *error;

	req->req = NULL;

	if (!result->success) {
		passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;
		error = result->error;
	} else if (!result->valid) {
		passdb_result = PASSDB_RESULT_PASSWORD_MISMATCH;
		error = "Invalid token";
	} else {
		db_oauth2_fields_merge(req, result->fields);
		if (req->token == NULL) {
			db_oauth2_callback(req, PASSDB_RESULT_INTERNAL_FAILURE,
					   "OAuth2 token missing from reply");
			return;
		} else if (db_oauth2_have_all_fields(req) &&
			   !req->db->set.force_introspection) {
			/* pass */
		} else if (*req->db->set.introspection_url != '\0') {
			db_oauth2_lookup_introspect(req);
			return;
		}
		db_oauth2_process_fields(req, &passdb_result, &error);
	}
	db_oauth2_callback(req, passdb_result, error);
}

static void
db_oauth2_lookup_passwd_grant(struct oauth2_request_result *result,
			      struct db_oauth2_request *req)
{
	enum passdb_result passdb_result;
	const char *error;
	const struct oauth2_field *f;

	req->req = NULL;

	if (!result->valid) {
		passdb_result = PASSDB_RESULT_INTERNAL_FAILURE;
		if (result->success) {
			error = NULL;
			array_foreach(result->fields, f) {
				if (strcmp(f->name, "error") == 0) {
					error = f->value;
					break;
				}
			}
			if (error != NULL &&
			    strcmp("invalid_grant", error) == 0) {
				passdb_result = PASSDB_RESULT_PASSWORD_MISMATCH;
			}
			if (error == NULL)
				error = "Internal error";
		} else
			error = result->error;
		db_oauth2_callback(req, passdb_result, error);
	} else {
		/* make sure token is NULL if no access_token is found */
		req->token = NULL;
		array_foreach(result->fields, f)
			if (strcmp(f->name, "access_token") == 0)
				req->token = p_strdup(req->pool, f->value);
		db_oauth2_lookup_continue(result, req);
	}
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
	input.local_ip = req->auth_request->local_ip;
	input.local_port = req->auth_request->local_port;
	input.remote_ip = req->auth_request->remote_ip;
	input.remote_port = req->auth_request->remote_port;
	input.real_local_ip = req->auth_request->real_local_ip;
	input.real_local_port = req->auth_request->real_local_port;
	input.real_remote_ip = req->auth_request->real_remote_ip;
	input.real_remote_port = req->auth_request->real_remote_port;
	input.service = req->auth_request->service;

	if (db->oauth2_set.key_dict != NULL) {
		/* try to validate token locally */
		e_debug(authdb_event(req->auth_request),
			"oauth2: Attempting to locally validate token");
		db_oauth2_local_validation(req, request->mech_password);
		return;

	}
	if (db->oauth2_set.use_grant_password) {
		e_debug(authdb_event(req->auth_request),
			"oauth2: Making grant url request to %s",
			db->set.grant_url);
		req->req = oauth2_passwd_grant_start(&db->oauth2_set, &input,
						     request->user, request->mech_password,
						     db_oauth2_lookup_passwd_grant, req);
	} else if (*db->oauth2_set.tokeninfo_url == '\0') {
		e_debug(authdb_event(req->auth_request),
			"oauth2: Making introspection request to %s",
			db->set.introspection_url);
		req->req = oauth2_introspection_start(&req->db->oauth2_set, &input,
						      db_oauth2_introspect_continue, req);
	} else {
		e_debug(authdb_event(req->auth_request),
			"oauth2: Making token validation lookup to %s",
			db->oauth2_set.tokeninfo_url);
		req->req = oauth2_token_validation_start(&db->oauth2_set, &input,
							 db_oauth2_lookup_continue, req);
	}
	i_assert(req->req != NULL);
	DLLIST_PREPEND(&db->head, req);
}

bool db_oauth2_uses_password_grant(const struct db_oauth2 *db)
{
	return db->set.use_grant_password;
}
