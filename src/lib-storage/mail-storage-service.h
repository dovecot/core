#ifndef MAIL_STORAGE_SERVICE_H
#define MAIL_STORAGE_SERVICE_H

#include "network.h"

struct master_service;

enum mail_storage_service_flags {
	/* Fail if we don't drop root privileges */
	MAIL_STORAGE_SERVICE_FLAG_DISALLOW_ROOT		= 0x01,
	/* Lookup user from userdb */
	MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP		= 0x02,
	/* Force mail_debug=yes */
	MAIL_STORAGE_SERVICE_FLAG_DEBUG			= 0x04,
	/* Keep the current process permissions */
	MAIL_STORAGE_SERVICE_FLAG_NO_RESTRICT_ACCESS	= 0x08,
	/* Get the process permissions from environment */
	MAIL_STORAGE_SERVICE_FLAG_RESTRICT_BY_ENV	= 0x10,
	/* Don't chdir() to user's home */
	MAIL_STORAGE_SERVICE_FLAG_NO_CHDIR		= 0x20
};

struct mail_storage_service_input {
	const char *module;
	const char *service;
	const char *username;
	struct ip_addr local_ip, remote_ip;

	const char *const *userdb_fields;
};

struct setting_parser_info;
struct mail_storage_service_multi_user;

struct mail_user *
mail_storage_service_init_user(struct master_service *service,
			       const struct mail_storage_service_input *input,
			       const struct setting_parser_info *set_roots[],
			       enum mail_storage_service_flags flags);
void mail_storage_service_deinit_user(void);

struct mail_storage_service_multi_ctx *
mail_storage_service_multi_init(struct master_service *service,
				const struct setting_parser_info *set_roots[],
				enum mail_storage_service_flags flags);
struct auth_master_connection *
mail_storage_service_multi_get_auth_conn(struct mail_storage_service_multi_ctx *ctx);
/* Returns 1 if ok, 0 if user wasn't found, -1 if error. */
int mail_storage_service_multi_lookup(struct mail_storage_service_multi_ctx *ctx,
				      const struct mail_storage_service_input *input,
				      pool_t pool,
				      struct mail_storage_service_multi_user **user_r,
				      const char **error_r);
int mail_storage_service_multi_next(struct mail_storage_service_multi_ctx *ctx,
				    struct mail_storage_service_multi_user *user,
				    struct mail_user **mail_user_r,
				    const char **error_r);
void mail_storage_service_multi_user_free(struct mail_storage_service_multi_user *user);
/* Initialize iterating through all users. Return the number of users. */
unsigned int
mail_storage_service_multi_all_init(struct mail_storage_service_multi_ctx *ctx);
/* Iterate through all usernames. Returns 1 if username was returned, 0 if
   there are no more users, -1 if error. */
int mail_storage_service_multi_all_next(struct mail_storage_service_multi_ctx *ctx,
					const char **username_r);
void mail_storage_service_multi_deinit(struct mail_storage_service_multi_ctx **ctx);

/* Return the settings pointed to by set_root parameter in _init().
   The settings contain all the changes done by userdb lookups. */
void *mail_storage_service_multi_user_get_set(struct mail_storage_service_multi_user *user);

/* Return the settings pointed to by set_root parameter in _init() */
void *mail_storage_service_get_settings(struct master_service *service);

#endif
