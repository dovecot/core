#ifndef __AUTH_REQUEST_H
#define __AUTH_REQUEST_H

#include "network.h"
#include "mech.h"
#include "userdb.h"
#include "passdb.h"

struct auth_client_connection;

struct auth_request {
	int refcount;

	pool_t pool;
	char *user;
	char *mech_password; /* set if verify_plain() is called */
	char *passdb_password; /* set after password lookup if successful */
	string_t *extra_fields;

	struct mech_module *mech;
	struct auth *auth;

	unsigned int connect_uid;
	unsigned int client_pid;
	unsigned int id;
	time_t created;

	const char *service;
	struct ip_addr local_ip, remote_ip;

	union {
		verify_plain_callback_t *verify_plain;
                lookup_credentials_callback_t *lookup_credentials;
	} private_callback;

	mech_callback_t *callback;
	void *context;

	unsigned int successful:1;
	unsigned int internal_failure:1;
	unsigned int finished:1;
	unsigned int delayed_failure:1;
	unsigned int accept_input:1;
	unsigned int no_failure_delay:1;
	unsigned int no_login:1;
	unsigned int proxy:1;
	/* ... mechanism specific data ... */
};

struct auth_request *
auth_request_new(struct auth *auth, struct mech_module *mech,
		 mech_callback_t *callback, void *context);
void auth_request_ref(struct auth_request *request);
int auth_request_unref(struct auth_request *request);

void auth_request_success(struct auth_request *request,
			  const void *data, size_t data_size);
void auth_request_fail(struct auth_request *request);
void auth_request_internal_failure(struct auth_request *request);

void auth_request_initial(struct auth_request *request,
			  const unsigned char *data, size_t data_size);
void auth_request_continue(struct auth_request *request,
			   const unsigned char *data, size_t data_size);

void auth_request_verify_plain(struct auth_request *request,
			       const char *password,
			       verify_plain_callback_t *callback);
void auth_request_lookup_credentials(struct auth_request *request,
				     enum passdb_credentials credentials,
				     lookup_credentials_callback_t *callback);
void auth_request_lookup_user(struct auth_request *request,
			      userdb_callback_t *callback, void *context);

int auth_request_set_username(struct auth_request *request,
			      const char *username, const char **error_r);

void auth_request_set_field(struct auth_request *request,
			    const char *name, const char *value);

const struct var_expand_table *
auth_request_get_var_expand_table(const struct auth_request *auth_request,
				  const char *(*escape_func)(const char *));

void auth_request_log_debug(struct auth_request *auth_request,
			    const char *subsystem,
			    const char *format, ...) __attr_format__(3, 4);
void auth_request_log_info(struct auth_request *auth_request,
			   const char *subsystem,
			   const char *format, ...) __attr_format__(3, 4);
void auth_request_log_error(struct auth_request *auth_request,
			    const char *subsystem,
			    const char *format, ...) __attr_format__(3, 4);

#endif
