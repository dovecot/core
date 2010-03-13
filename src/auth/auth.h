#ifndef AUTH_H
#define AUTH_H

#include "auth-settings.h"

#define PASSWORD_HIDDEN_STR "<hidden>"

struct auth_passdb {
	struct auth_passdb *next;

	const struct auth_passdb_settings *set;
	struct passdb_module *passdb;
};

struct auth_userdb {
	struct auth_userdb *next;

	const struct auth_userdb_settings *set;
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
