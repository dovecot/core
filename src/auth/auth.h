#ifndef __AUTH_H
#define __AUTH_H

#define PASSWORD_HIDDEN_STR "<hidden>"

struct auth_passdb {
	struct auth *auth;
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
	struct auth *auth;
	struct auth_userdb *next;

	unsigned int num;
	const char *args;
	struct userdb_module *userdb;
};

struct auth {
	pool_t pool;

	struct mech_module_list *mech_modules;
	buffer_t *mech_handshake;

	struct auth_passdb *masterdbs;
	struct auth_passdb *passdbs;
	struct auth_userdb *userdbs;

	const char *const *auth_realms;
	const char *default_realm;
	const char *anonymous_username;
	const char *username_format;
	const char *gssapi_hostname;
	char username_chars[256];
	char username_translation[256];
	char master_user_separator;
	bool ssl_require_client_cert;
        bool ssl_username_from_cert;

	bool verbose, verbose_debug, verbose_debug_passwords;
};

const string_t *auth_mechanisms_get_list(struct auth *auth);

struct auth *auth_preinit(void);
void auth_init(struct auth *auth);
void auth_deinit(struct auth **auth);

#endif
