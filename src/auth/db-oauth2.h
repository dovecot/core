#ifndef DB_OAUTH2_H
#define DB_OAUTH2_H 1

struct db_oauth2;
struct oauth2_request;
struct db_oauth2_request;

struct auth_oauth2_settings {
	pool_t pool;
	/* tokeninfo endpoint, format https://endpoint/somewhere?token= */
	const char *tokeninfo_url;
	/* password grant endpoint, format https://endpoint/somewhere */
	const char *grant_url;
	/* introspection endpoint, format https://endpoint/somewhere */
	const char *introspection_url;
	/* expected scope(s), optional */
	ARRAY_TYPE(const_string) scope;
	/* mode of introspection, one of auth, get, post, local
	   - auth: send token with header Authorization: Bearer token
	   - get: append token to url
	   - post: send token=<token> as POST request
	   - local: perform local validation
	*/
	const char *introspection_mode;
	/* normalization var-expand template for username, defaults to %Lu */
	const char *username_validation_format;
	/* name of username attribute to lookup, mandatory */
	const char *username_attribute;
	/* name of account is active attribute, optional */
	const char *active_attribute;
	/* expected active value for active attribute, optional */
	const char *active_value;
	/* client identifier for oauth2 server */
	const char *client_id;
	/* not really used, but have to present by oauth2 specs */
	const char *client_secret;
	/* valid token issuers */
	ARRAY_TYPE(const_string) issuers;
	/* The URL for a document following the OpenID Provider Configuration
	   Information schema, see

	   https://datatracker.ietf.org/doc/html/rfc7628#section-3.2.2
	*/
	const char *openid_configuration_url;

	/* Should introspection be done even if not necessary */
	bool force_introspection;
	/* Should we send service and local/remote endpoints as X-Dovecot-Auth headers */
	bool send_auth_headers;
	bool use_worker_with_mech;
};

struct auth_oauth2_post_settings {
	pool_t pool;
	ARRAY_TYPE(const_string) fields;
};

typedef void db_oauth2_lookup_callback_t(struct db_oauth2_request *request,
					 enum passdb_result result,
					 const char *error,
					 void *context);
struct db_oauth2_request {
	pool_t pool;
	struct db_oauth2_request *prev,*next;

	struct db_oauth2 *db;
	struct oauth2_request *req;

	/* username to match */
	const char *username;
	/* token to use */
	const char *token;

	struct auth_request *auth_request;
	struct auth_fields *fields;

	db_oauth2_lookup_callback_t *callback;
	void *context;
	verify_plain_callback_t *verify_callback;
};


int db_oauth2_init(struct event *event, bool use_grant_password, struct db_oauth2 **db_r,
		   const char **error_r);

bool db_oauth2_use_worker(const struct db_oauth2 *db);

const char *db_oauth2_get_openid_configuration_url(const struct db_oauth2 *db);

void db_oauth2_lookup(struct db_oauth2 *db, struct db_oauth2_request *req, const char *token, struct auth_request *request, db_oauth2_lookup_callback_t *callback, void *context);
#define db_oauth2_lookup(db, req, token, request, callback, context) \
	db_oauth2_lookup(db, req, token - \
		CALLBACK_TYPECHECK(callback, void(*)(struct db_oauth2_request *, enum passdb_result, const char*, typeof(context))), \
		request, (db_oauth2_lookup_callback_t*)callback, (void*)context)

void db_oauth2_deinit(void);

extern const struct setting_parser_info auth_oauth2_setting_parser_info;

#endif
