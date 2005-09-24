#ifndef __AUTH_H
#define __AUTH_H

struct auth_passdb {
	struct auth *auth;
	struct auth_passdb *next;

	unsigned int num;
	const char *args;
	struct passdb_module *passdb;
#ifdef HAVE_MODULES
	struct auth_module *module;
#endif
        /* if user is found from this passdb, deny authentication immediately */
	unsigned int deny:1;
};

struct auth_userdb {
	struct auth *auth;
	struct auth_userdb *next;

	unsigned int num;
	const char *args;
	struct userdb_module *userdb;
#ifdef HAVE_MODULES
	struct auth_module *module;
#endif
};

struct auth {
	pool_t pool;

	struct mech_module_list *mech_modules;
	buffer_t *mech_handshake;

	struct auth_passdb *passdbs;
	struct auth_userdb *userdbs;

	const char *const *auth_realms;
	const char *default_realm;
	const char *anonymous_username;
	char username_chars[256];
        char username_translation[256];
	int ssl_require_client_cert;

	int verbose, verbose_debug;
};

const string_t *auth_mechanisms_get_list(struct auth *auth);

struct auth *auth_preinit(void);
void auth_init(struct auth *auth);
void auth_deinit(struct auth *auth);

#endif
