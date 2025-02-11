#ifndef AUTH_H
#define AUTH_H

#include "md5.h"
#include "auth-settings.h"

#define PASSWORD_HIDDEN_STR "<hidden>"

ARRAY_DEFINE_TYPE(auth, struct auth *);
extern ARRAY_TYPE(auth) auths;

enum auth_passdb_skip {
	AUTH_PASSDB_SKIP_NEVER,
	AUTH_PASSDB_SKIP_AUTHENTICATED,
	AUTH_PASSDB_SKIP_UNAUTHENTICATED
};

enum auth_userdb_skip {
	AUTH_USERDB_SKIP_NEVER,
	AUTH_USERDB_SKIP_FOUND,
	AUTH_USERDB_SKIP_NOTFOUND
};

enum auth_db_rule {
	AUTH_DB_RULE_RETURN,
	AUTH_DB_RULE_RETURN_OK,
	AUTH_DB_RULE_RETURN_FAIL,
	AUTH_DB_RULE_CONTINUE,
	AUTH_DB_RULE_CONTINUE_OK,
	AUTH_DB_RULE_CONTINUE_FAIL
};

struct auth_passdb {
	struct auth_passdb *next;

	const char *name;
	const struct auth_settings *auth_set;
	const struct auth_passdb_settings *set;
	const struct auth_passdb_post_settings *unexpanded_post_set;
	struct passdb_module *passdb;

	/* The caching key for this passdb, or NULL if caching isn't wanted. */
	const char *cache_key;

	/* Authentication mechanisms filter, NULL is all, {NULL} is none */
	const char *const *mechanisms_filter;
	/* Username filter, NULL is no filter */
	const char *const *username_filter;

	enum auth_passdb_skip skip;
	enum auth_db_rule result_success;
	enum auth_db_rule result_failure;
	enum auth_db_rule result_internalfail;
};

struct auth_userdb {
	struct auth_userdb *next;

	const char *name;
	const struct auth_settings *auth_set;
	const struct auth_userdb_settings *set;
	const struct auth_userdb_post_settings *unexpanded_post_set;
	struct userdb_module *userdb;

	/* The caching key for this userdb, or NULL if caching isn't wanted. */
	const char *cache_key;

	enum auth_userdb_skip skip;
	enum auth_db_rule result_success;
	enum auth_db_rule result_failure;
	enum auth_db_rule result_internalfail;
};

struct auth {
	pool_t pool;
	const char *protocol;
	const struct auth_settings *protocol_set;

	const struct mechanisms_register *reg;
	struct auth_passdb *masterdbs;
	struct auth_passdb *passdbs;
	struct auth_userdb *userdbs;

	struct dns_client *dns_client;
};

extern bool shutting_down;

struct auth *auth_find_protocol(const char *name);
struct auth *auth_default_protocol(void);

void auth_passdbs_generate_md5(unsigned char md5[STATIC_ARRAY MD5_RESULTLEN]);
void auth_userdbs_generate_md5(unsigned char md5[STATIC_ARRAY MD5_RESULTLEN]);

void auths_preinit(struct event *parent_event,
		   const struct auth_settings *set,
		   const struct mechanisms_register *reg,
		   const char *const *protocols);
void auths_init(void);
void auths_deinit(void);
void auths_free(void);

#endif
