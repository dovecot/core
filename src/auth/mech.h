#ifndef __MECH_H
#define __MECH_H

#include "network.h"
#include "auth-client-interface.h"

struct auth_client_connection;

typedef void mech_callback_t(struct auth_client_request_reply *reply,
			     const void *data,
			     struct auth_client_connection *conn);

struct auth_request {
	int refcount;

	pool_t pool;
	char *user;

	struct auth_client_connection *conn;
	unsigned int id;
	time_t created;

	char *protocol;
	struct ip_addr local_ip, remote_ip;
	mech_callback_t *callback;

	int (*auth_initial)(struct auth_request *auth_request,
                            struct auth_client_request_new *request,
			    const unsigned char *data,
			    mech_callback_t *callback);
	int (*auth_continue)(struct auth_request *auth_request,
			     const unsigned char *data, size_t data_size,
			     mech_callback_t *callback);
	void (*auth_free)(struct auth_request *auth_request);
	/* ... mechanism specific data ... */
};

struct mech_module {
	const char *mech_name;

	unsigned int plaintext:1;
	unsigned int advertise:1;
	unsigned int passdb_need_plain:1;
	unsigned int passdb_need_credentials:1;

	struct auth_request *(*auth_new)(void);
};

struct mech_module_list {
	struct mech_module_list *next;

	struct mech_module module;
};

extern struct mech_module_list *mech_modules;
extern const char *const *auth_realms;
extern const char *default_realm;
extern const char *anonymous_username;
extern char username_chars[256];
extern int ssl_require_client_cert;

void mech_register_module(struct mech_module *module);
void mech_unregister_module(struct mech_module *module);

const string_t *auth_mechanisms_get_list(void);

void mech_request_new(struct auth_client_connection *conn,
		      struct auth_client_request_new *request,
		      const unsigned char *data,
		      mech_callback_t *callback);
void mech_request_continue(struct auth_client_connection *conn,
			   struct auth_client_request_continue *request,
			   const unsigned char *data,
			   mech_callback_t *callback);
void mech_request_free(struct auth_request *auth_request, unsigned int id);

void mech_init_auth_client_reply(struct auth_client_request_reply *reply);
void *mech_auth_success(struct auth_client_request_reply *reply,
			struct auth_request *auth_request,
			const void *data, size_t data_size);
void mech_auth_finish(struct auth_request *auth_request,
		      const void *data, size_t data_size, int success);

int mech_is_valid_username(const char *username);

void mech_cyrus_sasl_init_lib(void);
struct auth_request *
mech_cyrus_sasl_new(struct auth_client_connection *conn,
		    struct auth_client_request_new *request,
		    const unsigned char *data,
		    mech_callback_t *callback);

void auth_request_ref(struct auth_request *request);
int auth_request_unref(struct auth_request *request);

const struct var_expand_table *
auth_request_get_var_expand_table(const struct auth_request *auth_request,
				  const char *(*escape_func)(const char *));

void mech_init(void);
void mech_deinit(void);

#endif
