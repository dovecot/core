#ifndef __MECH_H
#define __MECH_H

#include "network.h"
#include "auth-client-interface.h"

enum auth_client_result {
	AUTH_CLIENT_RESULT_CONTINUE = 1,
	AUTH_CLIENT_RESULT_SUCCESS,
	AUTH_CLIENT_RESULT_FAILURE
};

struct auth_request;
struct auth_client_connection;

typedef void mech_callback_t(struct auth_request *request,
			     enum auth_client_result result,
			     const void *reply, size_t reply_size);

struct auth_request {
	int refcount;

	pool_t pool;
	char *user;
	const char *extra_fields;

	struct mech_module *mech;
	struct auth_client_connection *conn;

	unsigned int id;
	time_t created;

	const char *service;
	struct ip_addr local_ip, remote_ip;
	mech_callback_t *callback;

	unsigned int accept_input:1;
	unsigned int no_failure_delay:1;
	unsigned int no_login:1;
	unsigned int proxy:1;
	/* ... mechanism specific data ... */
};

struct mech_module {
	const char *mech_name;

        enum mech_security_flags flags;
	unsigned int passdb_need_plain:1;
	unsigned int passdb_need_credentials:1;

	struct auth_request *(*auth_new)(void);
	void (*auth_initial)(struct auth_request *request,
			     const unsigned char *data, size_t data_size,
			     mech_callback_t *callback);
	void (*auth_continue)(struct auth_request *request,
			      const unsigned char *data, size_t data_size,
			      mech_callback_t *callback);
	void (*auth_free)(struct auth_request *request);
};

struct mech_module_list {
	struct mech_module_list *next;

	struct mech_module module;
};

extern struct mech_module_list *mech_modules;
extern buffer_t *mech_handshake;

extern const char *const *auth_realms;
extern const char *default_realm;
extern const char *anonymous_username;
extern char username_chars[256];
extern int ssl_require_client_cert;

void mech_register_module(struct mech_module *module);
void mech_unregister_module(struct mech_module *module);
struct mech_module *mech_module_find(const char *name);

const string_t *auth_mechanisms_get_list(void);

void mech_auth_finish(struct auth_request *request,
		      const void *data, size_t data_size, int success);

int mech_fix_username(char *username, const char **error_r);

struct auth_request *auth_request_new(struct mech_module *mech);
void auth_request_destroy(struct auth_request *request);
void auth_request_ref(struct auth_request *request);
int auth_request_unref(struct auth_request *request);

const struct var_expand_table *
auth_request_get_var_expand_table(const struct auth_request *auth_request,
				  const char *(*escape_func)(const char *));

const char *get_log_prefix(const struct auth_request *auth_request);

void auth_failure_buf_flush(void);

void mech_init(void);
void mech_deinit(void);

#endif
