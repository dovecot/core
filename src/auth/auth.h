#ifndef AUTH_H
#define AUTH_H

#include "auth-settings.h"

#define PASSWORD_HIDDEN_STR "<hidden>"

struct auth_passdb {
	pool_t pool;
	struct auth_passdb *next;

        /* id is used by blocking passdb to identify the passdb */
	unsigned int id;
	const char *args;
	struct passdb_module *passdb;

        /* if user is found from this passdb, deny authentication immediately */
	unsigned int deny:1;
	/* after a successful lookup, continue to next passdb */
	unsigned int pass:1;
};

struct auth_userdb {
	pool_t pool;
	struct auth_userdb *next;

	unsigned int num;
	const char *args;
	struct userdb_module *userdb;
};

struct auth {
	pool_t pool;
	const struct auth_settings *set;

	struct mech_module_list *mech_modules;
	buffer_t *mech_handshake;

	struct auth_passdb *masterdbs;
	struct auth_passdb *passdbs;
	struct auth_userdb *userdbs;
};

const string_t *auth_mechanisms_get_list(struct auth *auth);

struct auth *auth_preinit(struct auth_settings *set);
void auth_init(struct auth *auth);
void auth_deinit(struct auth **auth);

#endif
