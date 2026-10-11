#ifndef OAUTH2_H
#define OAUTH2_H

#include "net.h"
#include "http-url.h"

struct dict;
struct oauth2_request;
struct oauth2_validation_key_cache;
struct var_expand_program;

struct oauth2_field {
	const char *name;
	const char *value;
};

ARRAY_DEFINE_TYPE(oauth2_field, struct oauth2_field);

struct oauth2_settings {
	struct http_client *client;
	/* GET tokeninfo from this URL, token is appended to URL
	   http://some.host/path?access_token= */
	const char *tokeninfo_url;
	/* POST grant password here, needs user credentials and client_*
	   settings. Points into the settings struct that owns it and is
	   never NULL; use http_url_is_empty() to test for unset. */
	const struct http_url *grant_url;
	/* GET more information from this URL, uses Bearer authentication */
	const char *introspection_url;
	/* POST refresh here, needs refresh token and client_* settings.
	   Never assigned by any caller today; oauth2_refresh_start() is
	   unreachable. */
	const struct http_url *refresh_url;
	/* client identifier for oauth2 server */
	const char *client_id;
	/* client secret for oauth2 server */
	const char *client_secret;
	/* access request scope for oauth2 server (optional) */
	const char *scope;
	/* key dict for looking up validation keys */
	struct dict *key_dict;
	/* cache for validation keys */
	struct oauth2_validation_key_cache *key_cache;
	/* valid issuer names */
	const char *const *issuers;
	/* How many seconds after token expiration is it still allowed to
	   succeed the authentication. */
	unsigned int token_expire_grace_secs;

	enum {
		INTROSPECTION_MODE_GET_AUTH,
		INTROSPECTION_MODE_GET,
		INTROSPECTION_MODE_POST,
		INTROSPECTION_MODE_LOCAL,
	} introspection_mode;
	/* Should X-Dovecot-Auth-* headers be sent */
	bool send_auth_headers;
	/* Should use grant password mechanism for authentication */
	bool use_grant_password;
};


struct oauth2_request_result {
	/* Oauth2 server response fields */
	ARRAY_TYPE(oauth2_field) *fields;
	/* Non-NULL if there was an unexpected internal error. */
	const char *error;
	/* timestamp token expires at */
	time_t expires_at;
	/* User authenticated successfully. Implies that error==NULL. */
	bool valid:1;
};

struct oauth2_request_input {
	const char *token;
	const char *protocol;
	struct ip_addr local_ip, real_local_ip, remote_ip, real_remote_ip;
	in_port_t local_port, real_local_port, remote_port, real_remote_port;
};

typedef void
oauth2_request_callback_t(struct oauth2_request_result*, void*);

bool oauth2_valid_token(const char *token);

/* Check where url_template places its variables, looking only at its literal
   text: %{access_token} must be in the URL path or query, and a variable that
   is part of the scheme, host or port must use the safe filter, because
   oauth2_url_template_expand() escapes all other variables. A variable in the
   userinfo (before "@") is escaped as usual. Returns 0 if fine, otherwise -1
   with error_r set. */
int oauth2_url_template_check(const struct var_expand_program *url_template,
			      const char **error_r);
/* Expand url_template with %{access_token} set to token, appending the
   result to dest. Every variable except those with the safe filter is
   percent-encoded, so filters see the raw token. Fails if a variable
   expands to "." or ".." (a dot segment, which would escape the intended URL
   path on a server that resolves them), if %{access_token} doesn't follow
   scheme://authority/ (or ?) after expansion, or if the template's own
   expansion fails. */
int oauth2_url_template_expand(const struct var_expand_program *url_template,
			       const char *token, string_t *dest,
			       const char **error_r);

struct oauth2_request*
oauth2_passwd_grant_start(const struct oauth2_settings *set,
			  const struct oauth2_request_input *input,
			  const char *username,
			  const char *password,
			  oauth2_request_callback_t *callback,
			  void *context);
#define oauth2_passwd_grant_start(set, input, username, password, callback, \
				  context) \
	oauth2_passwd_grant_start( \
		set, input - CALLBACK_TYPECHECK( \
			callback, void(*)(struct oauth2_request_result*, \
					  typeof(context))), \
		username, password, \
		(oauth2_request_callback_t*)callback, (void*)context);

struct oauth2_request*
oauth2_token_validation_start(const struct oauth2_settings *set,
			      const struct oauth2_request_input *input,
			      oauth2_request_callback_t *callback,
			      void *context);
#define oauth2_token_validation_start(set, input, callback, context) \
	oauth2_token_validation_start( \
		set, input - CALLBACK_TYPECHECK( \
			callback, void(*)(struct oauth2_request_result*, \
					  typeof(context))), \
		(oauth2_request_callback_t*)callback, (void*)context);

struct oauth2_request*
oauth2_introspection_start(const struct oauth2_settings *set,
			   const struct oauth2_request_input *input,
			   oauth2_request_callback_t *callback,
			   void *context);
#define oauth2_introspection_start(set, input, callback, context) \
	oauth2_introspection_start( \
		set, input - CALLBACK_TYPECHECK( \
			callback, void(*)(struct oauth2_request_result*, \
					  typeof(context))), \
		(oauth2_request_callback_t*)callback, (void*)context);

struct oauth2_request *
oauth2_refresh_start(const struct oauth2_settings *set,
		     const struct oauth2_request_input *input,
		     oauth2_request_callback_t *callback,
		     void *context);
#define oauth2_refresh_start(set, input, callback, context) \
	oauth2_refresh_start( \
		set, input - CALLBACK_TYPECHECK( \
			callback, void(*)(struct oauth2_request_result*, \
					  typeof(context))), \
		(oauth2_request_callback_t*)callback, (void*)context);

struct oauth2_request*
oauth2_client_secret_start(const struct oauth2_settings *set,
			  const struct oauth2_request_input *input,
			  const char *resource,
			  oauth2_request_callback_t *callback,
			  void *context);
#define oauth2_client_secret_start(set, input, resource, callback, \
				   context) \
	oauth2_client_secret_start( \
		set, input, resource - CALLBACK_TYPECHECK( \
			callback, void(*)(struct oauth2_request_result*, \
					  typeof(context))), \
		(oauth2_request_callback_t*)callback, (void*)context);

/* RFC 7523 JWT bearer assertion grant: POST the signed assertion to
   set->grant_url, along with client_id, client_secret and scope when set.
   The caller builds and signs the assertion. */
struct oauth2_request *
oauth2_jwt_bearer_grant_start(const struct oauth2_settings *set,
			      const struct oauth2_request_input *input,
			      const char *assertion,
			      oauth2_request_callback_t *callback,
			      void *context);
#define oauth2_jwt_bearer_grant_start(set, input, assertion, callback, \
				      context) \
	oauth2_jwt_bearer_grant_start( \
		set, input - CALLBACK_TYPECHECK( \
			callback, void(*)(struct oauth2_request_result*, \
					  typeof(context))), \
		assertion, \
		(oauth2_request_callback_t*)callback, (void*)context);

/* Abort without calling callback, use this to cancel the request */
void oauth2_request_abort(struct oauth2_request **);

int oauth2_try_parse_jwt(const struct oauth2_settings *set,
			 const char *token, ARRAY_TYPE(oauth2_field) *fields,
			 bool *is_jwt_r, const char **error_r);

/* Initialize validation key cache */
struct oauth2_validation_key_cache *oauth2_validation_key_cache_init(void);

/* Evict given key ID from cache, returns 0 on successful eviction */
int oauth2_validation_key_cache_evict(struct oauth2_validation_key_cache *cache,
				      const char *key_id);

/* Deinitialize validation key cache */
void oauth2_validation_key_cache_deinit(
	struct oauth2_validation_key_cache **_cache);

#endif
