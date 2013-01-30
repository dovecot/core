#ifndef AUTH_H
#define AUTH_H

#include "auth-settings.h"

#define PASSWORD_HIDDEN_STR "<hidden>"

enum auth_passdb_skip {
	AUTH_PASSDB_SKIP_NEVER,
	AUTH_PASSDB_SKIP_AUTHENTICATED,
	AUTH_PASSDB_SKIP_UNAUTHENTICATED
};

enum auth_passdb_rule {
	AUTH_PASSDB_RULE_RETURN,
	AUTH_PASSDB_RULE_RETURN_OK,
	AUTH_PASSDB_RULE_RETURN_FAIL,
	AUTH_PASSDB_RULE_CONTINUE,
	AUTH_PASSDB_RULE_CONTINUE_OK,
	AUTH_PASSDB_RULE_CONTINUE_FAIL
};

struct auth_passdb {
	struct auth_passdb *next;

	const struct auth_passdb_settings *set;
	struct passdb_module *passdb;

	enum auth_passdb_skip skip;
	enum auth_passdb_rule result_success;
	enum auth_passdb_rule result_failure;
	enum auth_passdb_rule result_internalfail;
};

struct auth_userdb {
	struct auth_userdb *next;

	const struct auth_userdb_settings *set;
	struct userdb_module *userdb;
};

struct auth {
	pool_t pool;
	const char *service;
	const struct auth_settings *set;

	const struct mechanisms_register *reg;
	struct auth_passdb *masterdbs;
	struct auth_passdb *passdbs;
	struct auth_userdb *userdbs;
};

extern struct auth_penalty *auth_penalty;

struct auth *auth_find_service(const char *name);
struct auth *auth_default_service(void);

void auths_preinit(const struct auth_settings *set, pool_t pool,
		   const struct mechanisms_register *reg,
		   const char *const *services);
void auths_init(void);
void auths_deinit(void);
void auths_free(void);

#endif
