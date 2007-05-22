#ifndef __MECH_H
#define __MECH_H

#include "auth-client-interface.h"

enum auth_client_result {
	AUTH_CLIENT_RESULT_CONTINUE = 1,
	AUTH_CLIENT_RESULT_SUCCESS,
	AUTH_CLIENT_RESULT_FAILURE
};

struct auth_request;

typedef void mech_callback_t(struct auth_request *request,
			     enum auth_client_result result,
			     const void *reply, size_t reply_size);

#include "auth-request.h"

/* Used only for string sanitization. */
#define MAX_MECH_NAME_LEN 64

struct mech_module {
	const char *mech_name;

        enum mech_security_flags flags;
	unsigned int passdb_need_plain:1;
	unsigned int passdb_need_credentials:1;
	unsigned int passdb_need_set_credentials:1;

	struct auth_request *(*auth_new)(void);
	void (*auth_initial)(struct auth_request *request,
			     const unsigned char *data, size_t data_size);
	void (*auth_continue)(struct auth_request *request,
			      const unsigned char *data, size_t data_size);
	void (*auth_free)(struct auth_request *request);
};

struct mech_module_list {
	struct mech_module_list *next;

	struct mech_module module;
};

void mech_register_module(const struct mech_module *module);
void mech_unregister_module(const struct mech_module *module);
struct mech_module *mech_module_find(const char *name);

void mech_generic_auth_initial(struct auth_request *request,
			       const unsigned char *data, size_t data_size);
void mech_generic_auth_free(struct auth_request *request);

void mech_init(void);
void mech_deinit(void);

#endif
