#ifndef AUTH_REQUEST_H
#define AUTH_REQUEST_H

#ifndef AUTH_REQUEST_FIELDS_CONST
#  define AUTH_REQUEST_FIELDS_CONST const
#endif

#include "array.h"
#include "net.h"
#include "var-expand.h"
#include "mech.h"
#include "userdb.h"
#include "passdb.h"
#include "auth-request-var-expand.h"
#include "password-scheme.h"

#define AUTH_REQUEST_USER_KEY_IGNORE " "

struct auth_client_connection;

enum auth_request_state {
	AUTH_REQUEST_STATE_NEW,
	AUTH_REQUEST_STATE_PASSDB,
	AUTH_REQUEST_STATE_MECH_CONTINUE,
	AUTH_REQUEST_STATE_FINISHED,
	AUTH_REQUEST_STATE_USERDB,

	AUTH_REQUEST_STATE_MAX
};

enum auth_request_conn_secured {
	AUTH_REQUEST_CONN_SECURED_NONE,
	AUTH_REQUEST_CONN_SECURED,
	AUTH_REQUEST_CONN_SECURED_TLS,
};

enum auth_request_cache_result {
	AUTH_REQUEST_CACHE_NONE,
	AUTH_REQUEST_CACHE_MISS,
	AUTH_REQUEST_CACHE_HIT,
};

/* All auth request fields are exported to auth-worker process. */
struct auth_request_fields {
        /* user contains the user who is being authenticated.
           When master user is logging in as someone else, it gets more
           complicated. Initially user is set to master's username and the
           requested_login_user is set to destination username. After masterdb
           has validated user as a valid master user, master_user is set to
           user and user is set to requested_login_user. */
        char *user, *requested_login_user, *master_user;
	/* original_username contains the username exactly as given by the
	   client. this is needed at least with DIGEST-MD5 for password
	   verification. however with master logins the master username has
	   been dropped from it. */
	const char *original_username;
	/* the username after doing all internal translations, but before
	   being changed by a db lookup */
	const char *translated_username;
	/* realm for the request, may be specified by some auth mechanisms */
	const char *realm;

	const char *service, *mech_name, *session_id, *local_name, *client_id;
	struct ip_addr local_ip, remote_ip, real_local_ip, real_remote_ip;
	in_port_t local_port, remote_port, real_local_port, real_remote_port;
	const char *ssl_ja3_hash;

        /* extra_fields are returned in authentication reply. Fields prefixed
           with "userdb_" are automatically placed to userdb_reply instead. */
        struct auth_fields *extra_fields;
	/* the whole userdb result reply */
	struct auth_fields *userdb_reply;

	/* Credentials from the first successful passdb lookup. These are used
	   as the final credentials, unless overridden by later passdb
	   lookups. Note that the requests in auth-worker processes see these
	   only as 1 byte sized \0 strings. */
	const unsigned char *delayed_credentials;
	size_t delayed_credentials_size;

	enum auth_request_conn_secured conn_secured;

	/* Authentication was successfully finished, including policy checks
	   and such. There may still be some final delay or final SASL
	   response. */
	bool successful:1;
	/* Password was verified successfully by a passdb. The following
	   passdbs shouldn't attempt to verify the password again. Note that
	   this differs from passdb_success, which may be set to FALSE due to
	   the result_* rules. */
	bool skip_password_check:1;

	/* flags received from auth client: */
	bool final_resp_ok:1;
	bool no_penalty:1;
	bool valid_client_cert:1;
	bool cert_username:1;
};

struct auth_request {
	int refcount;

	pool_t pool;

	struct event *event;
	struct event *mech_event;
	ARRAY(struct event *) authdb_event;

        enum auth_request_state state;
	char *mech_password; /* set if verify_plain() is called */
	char *passdb_password; /* set after password lookup if successful */
	struct auth_request_proxy_dns_lookup_ctx *dns_lookup_ctx;
	/* The final result of passdb lookup (delayed due to asynchronous
	   proxy DNS lookups) */
	enum passdb_result passdb_result;

	const struct mech_module *mech;
	const struct auth_settings *set;
        struct auth_passdb *passdb;
        struct auth_userdb *userdb;

	/* passdb lookups have a handler, userdb lookups don't */
	struct auth_request_handler *handler;
        struct auth_master_connection *master;

	/* FIXME: Remove this once mech-oauth2 correctly does the processing */
	const char *openid_config_url;

	unsigned int connect_uid;
	unsigned int client_pid;
	unsigned int id;
	time_t last_access;
	time_t delay_until;
	pid_t session_pid;

	/* These are const for most of the code, so they don't try to modify
	   the fields directly. Only auth-request-fields.c and unit tests have
	   the fields writable. This way it's more difficult to make them
	   out-of-sync with events. */
	AUTH_REQUEST_FIELDS_CONST struct auth_request_fields fields;

	struct timeout *to_abort, *to_penalty;
	unsigned int policy_penalty;
	unsigned int last_penalty;
	size_t initial_response_len;
	const unsigned char *initial_response;

	union {
		verify_plain_callback_t *verify_plain;
		lookup_credentials_callback_t *lookup_credentials;
		set_credentials_callback_t *set_credentials;
                userdb_callback_t *userdb;
	} private_callback;
	/* Used by passdb's credentials lookup to determine which scheme is
	   wanted by the caller. For example CRAM-MD5 SASL mechanism wants
	   CRAM-MD5 scheme for passwords.

	   When doing a PASS lookup (without authenticating), this is set to ""
	   to imply that caller accepts any kind of credentials. After the
	   credentials lookup is finished, this is set to the scheme that was
	   actually received.

	   Otherwise, this is kept as NULL. */
	const char *wanted_credentials_scheme;

	void *context;

	enum auth_request_cache_result passdb_cache_result;
	enum auth_request_cache_result userdb_cache_result;

	/* this is a lookup on auth socket (not login socket).
	   skip any proxying stuff if enabled. */
	bool auth_only:1;
	/* we're doing a userdb lookup now (we may have done passdb lookup
	   earlier) */
	bool userdb_lookup:1;
	/* DIGEST-MD5 kludge */
	bool domain_is_realm:1;

	bool request_auth_token:1;

	/* success/failure states: */
	bool failed:1; /* overrides any other success */
	bool internal_failure:1;
	bool passdbs_seen_user_unknown:1;
	bool passdbs_seen_internal_failure:1;
	bool userdbs_seen_internal_failure:1;

	/* current state: */
	bool handler_pending_reply:1;
	bool accept_cont_input:1;
	bool prefer_plain_credentials:1;
	bool in_delayed_failure_queue:1;
	bool removed_from_handler:1;
	bool snapshot_have_userdb_prefetch_set:1;
	/* username was changed by this passdb/userdb lookup. Used by
	   auth-workers to determine whether to send back a changed username. */
	bool user_changed_by_lookup:1;
	/* each passdb lookup can update the current success-status using the
	   result_* rules. the authentication succeeds only if this is TRUE
	   at the end. mechanisms that don't require passdb, but do a passdb
	   lookup anyway (e.g. GSSAPI) need to set this to TRUE by default. */
	bool passdb_success:1;
	/* userdb equivalent of passdb_success */
	bool userdb_success:1;
	/* the last userdb lookup failed either due to "tempfail" extra field
	   or because one of the returned uid/gid fields couldn't be translated
	   to a number */
	bool userdb_lookup_tempfailed:1;
	/* userdb_* fields have been set by the passdb lookup, userdb prefetch
	   will work. */
	bool userdb_prefetch_set:1;
	bool stats_sent:1;
	bool policy_refusal:1;
	bool policy_processed:1;

	bool event_finished_sent:1;

	/* ... mechanism specific data ... */
};

typedef void auth_request_proxy_cb_t(bool success, struct auth_request *);

extern unsigned int auth_request_state_count[AUTH_REQUEST_STATE_MAX];

extern const char auth_default_subsystems[2];
#define AUTH_SUBSYS_DB &auth_default_subsystems[0]
#define AUTH_SUBSYS_MECH &auth_default_subsystems[1]

struct auth_request *
auth_request_new(const struct mech_module *mech, struct event *parent_event);
struct auth_request *auth_request_new_dummy(struct event *parent_event);
void auth_request_init(struct auth_request *request);
struct auth *auth_request_get_auth(struct auth_request *request);

void auth_request_set_state(struct auth_request *request,
			    enum auth_request_state state);

void auth_request_ref(struct auth_request *request);
void auth_request_unref(struct auth_request **request);

void auth_request_success(struct auth_request *request,
			  const void *data, size_t data_size);
void auth_request_fail(struct auth_request *request);
void auth_request_internal_failure(struct auth_request *request);

void auth_request_export(struct auth_request *request, string_t *dest);
bool auth_request_import(struct auth_request *request,
			 const char *key, const char *value);
bool auth_request_import_info(struct auth_request *request,
			      const char *key, const char *value);
bool auth_request_import_auth(struct auth_request *request,
			      const char *key, const char *value);
bool auth_request_import_master(struct auth_request *request,
				const char *key, const char *value);

void auth_request_initial(struct auth_request *request);
void auth_request_continue(struct auth_request *request,
			   const unsigned char *data, size_t data_size);

void auth_request_verify_plain(struct auth_request *request,
			       const char *password,
			       verify_plain_callback_t *callback);
void auth_request_lookup_credentials(struct auth_request *request,
				     const char *scheme,
				     lookup_credentials_callback_t *callback);
void auth_request_lookup_user(struct auth_request *request,
			      userdb_callback_t *callback);

bool auth_request_set_username(struct auth_request *request,
			       const char *username, const char **error_r);
/* Change the username without any translations or checks. */
void auth_request_set_username_forced(struct auth_request *request,
				      const char *username);
bool auth_request_set_login_username(struct auth_request *request,
                                     const char *username,
                                     const char **error_r);
/* Change the login username without any translations or checks. */
void auth_request_set_login_username_forced(struct auth_request *request,
					    const char *username);
void auth_request_set_realm(struct auth_request *request, const char *realm);
/* Request was fully successfully authenticated, including policy checks etc. */
void auth_request_set_auth_successful(struct auth_request *request);
/* Password was successfully verified by a passdb. */
void auth_request_set_password_verified(struct auth_request *request);
/* Save credentials from a successful passdb lookup. */
void auth_request_set_delayed_credentials(struct auth_request *request,
					  const unsigned char *credentials,
					  size_t size);

void auth_request_set_field(struct auth_request *request,
			    const char *name, const char *value,
			    const char *default_scheme) ATTR_NULL(4);
void auth_request_set_null_field(struct auth_request *request, const char *name);
void auth_request_set_field_keyvalue(struct auth_request *request,
				     const char *field,
				     const char *default_scheme) ATTR_NULL(3);
void auth_request_set_fields(struct auth_request *request,
			     const char *const *fields,
			     const char *default_scheme) ATTR_NULL(3);

void auth_request_init_userdb_reply(struct auth_request *request,
				    bool add_default_fields);
void auth_request_set_userdb_field(struct auth_request *request,
				   const char *name, const char *value);
void auth_request_set_userdb_field_values(struct auth_request *request,
					  const char *name,
					  const char *const *values);
/* returns -1 = failed, 0 = callback is called later, 1 = finished */
int auth_request_proxy_finish(struct auth_request *request,
			      auth_request_proxy_cb_t *callback);
void auth_request_proxy_finish_failure(struct auth_request *request);

void auth_request_log_password_mismatch(struct auth_request *request,
					const char *subsystem);
enum passdb_result
auth_request_password_verify(struct auth_request *request,
			     const char *plain_password,
			     const char *crypted_password,
			     const char *scheme, const char *subsystem)
			     ATTR_WARN_UNUSED_RESULT;
enum passdb_result
auth_request_password_verify_log(struct auth_request *request,
				 const char *plain_password,
				 const char *crypted_password,
				 const char *scheme, const char *subsystem,
				 bool log_password_mismatch)
				 ATTR_WARN_UNUSED_RESULT;
enum passdb_result auth_request_password_missing(struct auth_request *request);

void auth_request_get_log_prefix(string_t *str, struct auth_request *auth_request,
				 const char *subsystem);

void auth_request_log_debug(struct auth_request *auth_request,
			    const char *subsystem,
			    const char *format, ...) ATTR_FORMAT(3, 4);
void auth_request_log_info(struct auth_request *auth_request,
			   const char *subsystem,
			   const char *format, ...) ATTR_FORMAT(3, 4);
void auth_request_log_warning(struct auth_request *auth_request,
			      const char *subsystem,
			      const char *format, ...) ATTR_FORMAT(3, 4);
void auth_request_log_error(struct auth_request *auth_request,
			    const char *subsystem,
			    const char *format, ...) ATTR_FORMAT(3, 4);
void auth_request_log_unknown_user(struct auth_request *auth_request,
				   const char *subsystem);

void auth_request_log_login_failure(struct auth_request *request,
				    const char *subsystem,
				    const char *message);
void
auth_request_verify_plain_callback_finish(enum passdb_result result,
                                          struct auth_request *request);
void auth_request_verify_plain_callback(enum passdb_result result,
					struct auth_request *request);
void auth_request_lookup_credentials_callback(enum passdb_result result,
					      const unsigned char *credentials,
					      size_t size,
					      struct auth_request *request);
void auth_request_set_credentials(struct auth_request *request,
				  const char *scheme, const char *data,
				  set_credentials_callback_t *callback);
void auth_request_userdb_callback(enum userdb_result result,
				  struct auth_request *request);
void auth_request_default_verify_plain_continue(struct auth_request *request,
						verify_plain_callback_t *callback);

void auth_request_refresh_last_access(struct auth_request *request);
void auth_str_append(string_t *dest, const char *key, const char *value);
bool auth_request_username_accepted(const char *const *filter, const char *username);
struct event_passthrough *
auth_request_finished_event(struct auth_request *request, struct event *event);
void auth_request_log_finished(struct auth_request *request);
void auth_request_master_user_login_finish(struct auth_request *request);
const char *auth_request_get_log_prefix_db(struct auth_request *auth_request);
void auth_request_fields_init(struct auth_request *request);

void auth_request_passdb_lookup_begin(struct auth_request *request);
void auth_request_passdb_lookup_end(struct auth_request *request,
				    enum passdb_result result);
void auth_request_userdb_lookup_begin(struct auth_request *request);
void auth_request_userdb_lookup_end(struct auth_request *request,
				    enum userdb_result result);

/* Fetches the current authdb event, this is done because
   some lookups can recurse into new lookups, requiring new event,
   which will be returned here. */
static inline struct event *authdb_event(const struct auth_request *request)
{
	if (array_count(&request->authdb_event) == 0)
		return request->event;
	struct event **e = array_back_modifiable(&request->authdb_event);
	return *e;
}

#endif
