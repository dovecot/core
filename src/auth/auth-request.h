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
	const char *extra_fields;

	struct mech_module *mech;
	struct auth *auth;
	struct auth_client_connection *conn;

	unsigned int id;
	time_t created;

	const char *service;
	struct ip_addr local_ip, remote_ip;
	mech_callback_t *callback;

	unsigned int successful:1;
	unsigned int internal_failure:1;
	unsigned int accept_input:1;
	unsigned int no_failure_delay:1;
	unsigned int no_login:1;
	unsigned int proxy:1;
	unsigned int destroyed:1;
	/* ... mechanism specific data ... */
};

void auth_request_success(struct auth_request *request,
			  const void *data, size_t data_size);
void auth_request_fail(struct auth_request *request);
void auth_request_internal_failure(struct auth_request *request);

struct auth_request *
auth_request_new(struct auth *auth, struct mech_module *mech,
		 mech_callback_t *callback);
void auth_request_destroy(struct auth_request *request);
void auth_request_ref(struct auth_request *request);
int auth_request_unref(struct auth_request *request);

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

struct auth_request_extra *
auth_request_extra_begin(struct auth_request *request, const char *password);
void auth_request_extra_next(struct auth_request_extra *extra,
			     const char *name, const char *value);
void auth_request_extra_finish(struct auth_request_extra *extra,
			       const char *cache_key);

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

void auth_failure_buf_flush(void);

void auth_requests_init(void);
void auth_requests_deinit(void);

#endif
