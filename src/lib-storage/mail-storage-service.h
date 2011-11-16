#ifndef MAIL_STORAGE_SERVICE_H
#define MAIL_STORAGE_SERVICE_H

#include "network.h"

struct master_service;
struct mail_user;
struct setting_parser_context;
struct setting_parser_info;
struct mail_storage_service_user;

enum mail_storage_service_flags {
	/* Fail if we don't drop root privileges */
	MAIL_STORAGE_SERVICE_FLAG_DISALLOW_ROOT		= 0x01,
	/* Lookup user from userdb */
	MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP		= 0x02,
	/* Force mail_debug=yes */
	MAIL_STORAGE_SERVICE_FLAG_DEBUG			= 0x04,
	/* Keep the current process permissions */
	MAIL_STORAGE_SERVICE_FLAG_NO_RESTRICT_ACCESS	= 0x08,
	/* Don't chdir() to user's home */
	MAIL_STORAGE_SERVICE_FLAG_NO_CHDIR		= 0x10,
	/* Drop privileges only temporarily (keep running as setuid-root) */
	MAIL_STORAGE_SERVICE_FLAG_TEMP_PRIV_DROP	= 0x20,
	/* Enable core dumps even when dropping privileges temporarily */
	MAIL_STORAGE_SERVICE_FLAG_ENABLE_CORE_DUMPS	= 0x40,
	/* Don't initialize logging or change log prefixes */
	MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT		= 0x80,
	/* Don't load plugins in _service_lookup() */
	MAIL_STORAGE_SERVICE_FLAG_NO_PLUGINS		= 0x100,
	/* Don't close auth connections because of idling. */
	MAIL_STORAGE_SERVICE_FLAG_NO_IDLE_TIMEOUT	= 0x200,
	/* When executing doveconf, tell it to use sysexits codes */
	MAIL_STORAGE_SERVICE_FLAG_USE_SYSEXITS		= 0x400,
	/* Don't create namespaces, only the user. */
	MAIL_STORAGE_SERVICE_FLAG_NO_NAMESPACES		= 0x800
};

struct mail_storage_service_input {
	const char *module;
	const char *service;
	const char *username;
	struct ip_addr local_ip, remote_ip;
	unsigned int local_port, remote_port;

	const char *const *userdb_fields;

	/* Override specified global flags */
	enum mail_storage_service_flags flags_override_add;
	enum mail_storage_service_flags flags_override_remove;

	/* override MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP for this lookup */
	unsigned int no_userdb_lookup:1;
};

extern struct module *mail_storage_service_modules;

struct mail_storage_service_ctx *
mail_storage_service_init(struct master_service *service,
			  const struct setting_parser_info *set_roots[],
			  enum mail_storage_service_flags flags);
struct auth_master_connection *
mail_storage_service_get_auth_conn(struct mail_storage_service_ctx *ctx);
int mail_storage_service_read_settings(struct mail_storage_service_ctx *ctx,
				       const struct mail_storage_service_input *input,
				       pool_t pool,
				       const struct setting_parser_info **user_info_r,
				       const struct setting_parser_context **parser_r,
				       const char **error_r);
/* Read settings and initialize context to use them. Do nothing if service is
   already initialized. This is mainly necessary when calling _get_auth_conn()
   or _all_init(). */
void mail_storage_service_init_settings(struct mail_storage_service_ctx *ctx,
					const struct mail_storage_service_input *input);
/* Returns 1 if ok, 0 if user wasn't found, -1 if fatal error,
   -2 if error is user-specific (e.g. invalid settings).
   Error can be safely shown to untrusted users. */
int mail_storage_service_lookup(struct mail_storage_service_ctx *ctx,
				const struct mail_storage_service_input *input,
				struct mail_storage_service_user **user_r,
				const char **error_r);
/* Returns 0 if ok, -1 if fatal error, -2 if error is user-specific. */
int mail_storage_service_next(struct mail_storage_service_ctx *ctx,
			      struct mail_storage_service_user *user,
			      struct mail_user **mail_user_r);
void mail_storage_service_restrict_setenv(struct mail_storage_service_ctx *ctx,
					  struct mail_storage_service_user *user);
/* Combine lookup() and next() into one call. */
int mail_storage_service_lookup_next(struct mail_storage_service_ctx *ctx,
				     const struct mail_storage_service_input *input,
				     struct mail_storage_service_user **user_r,
				     struct mail_user **mail_user_r,
				     const char **error_r);
void mail_storage_service_user_free(struct mail_storage_service_user **user);
/* Initialize iterating through all users. Return the number of users. */
unsigned int
mail_storage_service_all_init(struct mail_storage_service_ctx *ctx);
/* Iterate through all usernames. Returns 1 if username was returned, 0 if
   there are no more users, -1 if error. */
int mail_storage_service_all_next(struct mail_storage_service_ctx *ctx,
				  const char **username_r);
void mail_storage_service_deinit(struct mail_storage_service_ctx **ctx);

/* Return the settings pointed to by set_root parameter in _init().
   The settings contain all the changes done by userdb lookups. */
void **mail_storage_service_user_get_set(struct mail_storage_service_user *user);
const struct mail_storage_service_input *
mail_storage_service_user_get_input(struct mail_storage_service_user *user);
struct setting_parser_context *
mail_storage_service_user_get_settings_parser(struct mail_storage_service_user *user);

/* Return the settings pointed to by set_root parameter in _init() */
void *mail_storage_service_get_settings(struct master_service *service);

#endif
