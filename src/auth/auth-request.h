#ifndef AUTH_REQUEST_H
#define AUTH_REQUEST_H

#include "network.h"
#include "mech.h"
#include "userdb.h"
#include "passdb.h"

struct auth_client_connection;

enum auth_request_state {
	AUTH_REQUEST_STATE_NEW,
	AUTH_REQUEST_STATE_PASSDB,
	AUTH_REQUEST_STATE_MECH_CONTINUE,
	AUTH_REQUEST_STATE_FINISHED,
	AUTH_REQUEST_STATE_USERDB
};

typedef const char *
auth_request_escape_func_t(const char *string,
			   const struct auth_request *auth_request);

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
           with "userdb_" are skipped. If prefetch userdb is used, it uses
           the "userdb_" prefixed fields. */
        struct auth_stream_reply *extra_fields;
	/* extra_fields that aren't supposed to be sent to the client, but
	   are supposed to be stored to auth cache. */
	struct auth_stream_reply *extra_cache_fields;
	/* the whole userdb result reply */
	struct auth_stream_reply *userdb_reply;

	const struct mech_module *mech;
	struct auth *auth;
        struct auth_passdb *passdb;
        struct auth_userdb *userdb;

	unsigned int connect_uid;
	unsigned int client_pid;
	unsigned int id;
	time_t last_access;

	const char *service, *mech_name;
	struct ip_addr local_ip, remote_ip;
	unsigned int local_port, remote_port;

	struct timeout *to_penalty;
	unsigned int last_penalty;
	unsigned int initial_response_len;
	const unsigned char *initial_response;

	union {
		verify_plain_callback_t *verify_plain;
		lookup_credentials_callback_t *lookup_credentials;
		set_credentials_callback_t *set_credentials;
                userdb_callback_t *userdb;
	} private_callback;
        const char *credentials_scheme;

	mech_callback_t *callback;
	void *context;
        struct auth_master_connection *master;

	unsigned int successful:1;
	unsigned int passdb_failure:1;
	unsigned int internal_failure:1;
	unsigned int passdb_internal_failure:1;
	unsigned int userdb_internal_failure:1;
	unsigned int delayed_failure:1;
	unsigned int domain_is_realm:1;
	unsigned int accept_input:1;
	unsigned int no_failure_delay:1;
	unsigned int no_login:1;
	unsigned int no_password:1;
	unsigned int skip_password_check:1;
	unsigned int prefer_plain_credentials:1;
	unsigned int proxy:1;
	unsigned int proxy_maybe:1;
	unsigned int valid_client_cert:1;
	unsigned int cert_username:1;
	unsigned int userdb_lookup:1;
	unsigned int userdb_lookup_failed:1;
	unsigned int secured:1;

	/* ... mechanism specific data ... */
};

struct auth_request *
auth_request_new(struct auth *auth, const struct mech_module *mech,
		 mech_callback_t *callback, void *context);
struct auth_request *auth_request_new_dummy(struct auth *auth);
void auth_request_ref(struct auth_request *request);
void auth_request_unref(struct auth_request **request);

void auth_request_success(struct auth_request *request,
			  const void *data, size_t data_size);
void auth_request_fail(struct auth_request *request);
void auth_request_internal_failure(struct auth_request *request);

void auth_request_export(struct auth_request *request,
			 struct auth_stream_reply *reply);
bool auth_request_import(struct auth_request *request,
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
			    const char *default_scheme);
void auth_request_set_fields(struct auth_request *request,
			     const char *const *fields,
			     const char *default_scheme);

void auth_request_init_userdb_reply(struct auth_request *request);
void auth_request_set_userdb_field(struct auth_request *request,
				   const char *name, const char *value);
void auth_request_set_userdb_field_values(struct auth_request *request,
					  const char *name,
					  const char *const *values);
void auth_request_proxy_finish(struct auth_request *request, bool success);

int auth_request_password_verify(struct auth_request *request,
				 const char *plain_password,
				 const char *crypted_password,
				 const char *scheme, const char *subsystem);

const struct var_expand_table *
auth_request_get_var_expand_table(const struct auth_request *auth_request,
				  auth_request_escape_func_t *escape_func);
const char *auth_request_str_escape(const char *string,
				    const struct auth_request *request);

void auth_request_log_debug(struct auth_request *auth_request,
			    const char *subsystem,
			    const char *format, ...) ATTR_FORMAT(3, 4);
void auth_request_log_info(struct auth_request *auth_request,
			   const char *subsystem,
			   const char *format, ...) ATTR_FORMAT(3, 4);
void auth_request_log_error(struct auth_request *auth_request,
			    const char *subsystem,
			    const char *format, ...) ATTR_FORMAT(3, 4);

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

#endif
