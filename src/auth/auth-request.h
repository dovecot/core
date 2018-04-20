#ifndef AUTH_REQUEST_H
#define AUTH_REQUEST_H

#include "net.h"
#include "var-expand.h"
#include "mech.h"
#include "userdb.h"
#include "passdb.h"
#include "password-scheme.h"
#include "auth-request-var-expand.h"

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

struct auth_request {
	int refcount;

	pool_t pool;
	enum auth_request_state state;
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
	char *mech_password; /* set if verify_plain() is called */
	char *passdb_password; /* set after password lookup if successful */
	/* extra_fields are returned in authentication reply. Fields prefixed
	   with "userdb_" are automatically placed to userdb_reply instead. */
	/* the login/username and fingerprint given by the certificate */
	char *cert_loginname;
    char *cert_fingerprint;
    char *cert_fingerprint_base64;
	struct auth_fields *extra_fields;
	/* the whole userdb result reply */
	struct auth_fields *userdb_reply;
	struct auth_request_proxy_dns_lookup_ctx *dns_lookup_ctx;
	/* The final result of passdb lookup (delayed due to asynchronous
	   proxy DNS lookups) */
	enum passdb_result passdb_result;

	const struct mech_module *mech;
	const struct auth_settings *set;
        struct auth_passdb *passdb;
        struct auth_userdb *userdb;

	struct stats *stats;

	/* passdb lookups have a handler, userdb lookups don't */
	struct auth_request_handler *handler;
        struct auth_master_connection *master;

	unsigned int connect_uid;
	unsigned int client_pid;
	unsigned int id;
	time_t last_access;
	time_t delay_until;
	pid_t session_pid;

	const char *service, *mech_name, *session_id, *local_name, *client_id;
	struct ip_addr local_ip, remote_ip, real_local_ip, real_remote_ip;
	in_port_t local_port, remote_port, real_local_port, real_remote_port;

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
	const char *credentials_scheme;
	const unsigned char *delayed_credentials;
	size_t delayed_credentials_size;

	void *context;

	/* this is a lookup on auth socket (not login socket).
	   skip any proxying stuff if enabled. */
	unsigned int auth_only:1;
	/* we're doing a userdb lookup now (we may have done passdb lookup
	   earlier) */
	unsigned int userdb_lookup:1;
	/* DIGEST-MD5 kludge */
	unsigned int domain_is_realm:1;
	/* auth_debug is enabled for this request */
	unsigned int debug:1;

	/* flags received from auth client: */
	unsigned int secured:1;
	unsigned int final_resp_ok:1;
	unsigned int no_penalty:1;
	unsigned int valid_client_cert:1;
	unsigned int cert_username:1;
	unsigned int request_auth_token:1;

	/* success/failure states: */
	unsigned int successful:1;
	unsigned int failed:1; /* overrides any other success */
	unsigned int internal_failure:1;
	unsigned int passdbs_seen_user_unknown:1;
	unsigned int passdbs_seen_internal_failure:1;
	unsigned int userdbs_seen_internal_failure:1;

	/* current state: */
	unsigned int accept_cont_input:1;
	unsigned int skip_password_check:1;
	unsigned int prefer_plain_credentials:1;
	unsigned int in_delayed_failure_queue:1;
	unsigned int removed_from_handler:1;
	unsigned int snapshot_have_userdb_prefetch_set:1;
	/* username was changed by this passdb/userdb lookup. Used by
	   auth-workers to determine whether to send back a changed username. */
	unsigned int user_changed_by_lookup:1;
	/* each passdb lookup can update the current success-status using the
	   result_* rules. the authentication succeeds only if this is TRUE
	   at the end. mechanisms that don't require passdb, but do a passdb
	   lookup anyway (e.g. GSSAPI) need to set this to TRUE by default. */
	unsigned int passdb_success:1;
	/* userdb equivalent of passdb_success */
	unsigned int userdb_success:1;
	/* the last userdb lookup failed either due to "tempfail" extra field
	   or because one of the returned uid/gid fields couldn't be translated
	   to a number */
	unsigned int userdb_lookup_tempfailed:1;
	/* userdb_* fields have been set by the passdb lookup, userdb prefetch
	   will work. */
	unsigned int userdb_prefetch_set:1;
	/* userdb lookup's results are from cache */
	unsigned int userdb_result_from_cache:1;
	unsigned int stats_sent:1;
	unsigned int policy_refusal:1;
	unsigned int policy_processed:1;

	/* ... mechanism specific data ... */
};

typedef void auth_request_proxy_cb_t(bool success, struct auth_request *);

extern unsigned int auth_request_state_count[AUTH_REQUEST_STATE_MAX];

extern const char auth_default_subsystems[2];
#define AUTH_SUBSYS_DB &auth_default_subsystems[0]
#define AUTH_SUBSYS_MECH &auth_default_subsystems[1]

struct auth_request *
auth_request_new(const struct mech_module *mech);
struct auth_request *auth_request_new_dummy(void);
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
bool auth_request_set_login_username(struct auth_request *request,
                                     const char *username,
                                     const char **error_r);

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

void auth_request_init_userdb_reply(struct auth_request *request);
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
int auth_request_password_verify(struct auth_request *request,
				 const char *plain_password,
				 const char *crypted_password,
				 const char *scheme, const char *subsystem);

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

void auth_request_refresh_last_access(struct auth_request *request);
void auth_str_append(string_t *dest, const char *key, const char *value);
bool auth_request_username_accepted(const char *const *filter, const char *username);

#endif
