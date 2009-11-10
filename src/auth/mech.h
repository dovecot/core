#ifndef MECH_H
#define MECH_H

#include "auth-client-interface.h"

enum auth_client_result {
	AUTH_CLIENT_RESULT_CONTINUE = 1,
	AUTH_CLIENT_RESULT_SUCCESS,
	AUTH_CLIENT_RESULT_FAILURE
};

struct auth_settings;
struct auth_request;

typedef void mech_callback_t(struct auth_request *request,
			     enum auth_client_result result,
			     const void *reply, size_t reply_size);

#include "auth-request.h"

/* Used only for string sanitization. */
#define MAX_MECH_NAME_LEN 64

enum mech_passdb_need {
	/* Mechanism doesn't need a passdb at all */
	MECH_PASSDB_NEED_NOTHING = 0,
	/* Mechanism just needs to verify a given plaintext password */
	MECH_PASSDB_NEED_VERIFY_PLAIN,
	/* Mechanism needs to verify a given challenge+response combination,
	   i.e. there is only a single response from client.
	   (Currently implemented the same as _LOOKUP_CREDENTIALS) */
	MECH_PASSDB_NEED_VERIFY_RESPONSE,
	/* Mechanism needs to look up credentials with appropriate scheme */
	MECH_PASSDB_NEED_LOOKUP_CREDENTIALS,
	/* Mechanism needs to look up credentials and also modify them */
	MECH_PASSDB_NEED_SET_CREDENTIALS
};

struct mech_module {
	const char *mech_name;

	enum mech_security_flags flags;
	enum mech_passdb_need passdb_need;

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
const struct mech_module *mech_module_find(const char *name);

void mech_generic_auth_initial(struct auth_request *request,
			       const unsigned char *data, size_t data_size);
void mech_generic_auth_free(struct auth_request *request);

void mech_init(const struct auth_settings *set);
void mech_deinit(const struct auth_settings *set);

#endif
