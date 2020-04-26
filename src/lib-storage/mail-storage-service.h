#ifndef MAIL_STORAGE_SERVICE_H
#define MAIL_STORAGE_SERVICE_H

#include "net.h"

struct master_service;
struct mail_user;
struct setting_parser_context;
struct setting_parser_info;
struct mail_storage_service_user;

enum mail_storage_service_flags {
	/* Allow not dropping root privileges */
	MAIL_STORAGE_SERVICE_FLAG_ALLOW_ROOT		= 0x01,
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
	MAIL_STORAGE_SERVICE_FLAG_NO_NAMESPACES		= 0x800,
};

struct mail_storage_service_input {
	struct event *parent_event;

	const char *module;
	const char *service;
	const char *username;
	/* If set, use this string as the session ID */
	const char *session_id;
	/* If set, use this string as the session ID prefix, but also append
	   a unique session ID suffix to it. */
	const char *session_id_prefix;
	/* If non-zero, override timestamp when session was created and set
	   mail_user.session_restored=TRUE */
	time_t session_create_time;

	struct ip_addr local_ip, remote_ip;
	in_port_t local_port, remote_port;

	const char *const *userdb_fields;

	const char *forward_fields;

	/* Override specified global flags */
	enum mail_storage_service_flags flags_override_add;
	enum mail_storage_service_flags flags_override_remove;

	/* override MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP for this lookup */
	bool no_userdb_lookup:1;
	/* Enable auth_debug=yes for this lookup */
	bool debug:1;
	/* Connection is secure (SSL or just trusted) */
	bool conn_secured:1;
	/* Connection is secured using SSL specifically */
	bool conn_ssl_secured:1;
};

extern struct module *mail_storage_service_modules;

struct mail_storage_service_ctx *
mail_storage_service_init(struct master_service *service,
			  const struct setting_parser_info *set_roots[],
			  enum mail_storage_service_flags flags) ATTR_NULL(2);
struct auth_master_connection *
mail_storage_service_get_auth_conn(struct mail_storage_service_ctx *ctx);
/* Set auth connection (instead of creating a new one automatically). */
void mail_storage_service_set_auth_conn(struct mail_storage_service_ctx *ctx,
					struct auth_master_connection *conn);
int mail_storage_service_read_settings(struct mail_storage_service_ctx *ctx,
				       const struct mail_storage_service_input *input,
				       pool_t pool,
				       const struct setting_parser_info **user_info_r,
				       const struct setting_parser_context **parser_r,
				       const char **error_r) ATTR_NULL(2);
/* Read settings and initialize context to use them. Do nothing if service is
   already initialized. This is mainly necessary when calling _get_auth_conn()
   or _all_init(). */
void mail_storage_service_init_settings(struct mail_storage_service_ctx *ctx,
					const struct mail_storage_service_input *input)
	ATTR_NULL(2);
/* Returns 1 if ok, 0 if user wasn't found, -1 if fatal error,
   -2 if error is user-specific (e.g. invalid settings). */
int mail_storage_service_lookup(struct mail_storage_service_ctx *ctx,
				const struct mail_storage_service_input *input,
				struct mail_storage_service_user **user_r,
				const char **error_r);
/* The next mail_storage_service_lookup() will save the userdb fields into the
   given pointer, allocated from the given pool. */
void mail_storage_service_save_userdb_fields(struct mail_storage_service_ctx *ctx,
					     pool_t pool, const char *const **userdb_fields_r);
/* Returns 0 if ok, -1 if fatal error, -2 if error is user-specific. */
int mail_storage_service_next(struct mail_storage_service_ctx *ctx,
			      struct mail_storage_service_user *user,
			      struct mail_user **mail_user_r,
			      const char **error_r);
/* Returns 0 if ok, -1 if fatal error, -2 if error is user-specific. */
int mail_storage_service_next_with_session_suffix(struct mail_storage_service_ctx *ctx,
						  struct mail_storage_service_user *user,
						  const char *session_id_postfix,
						  struct mail_user **mail_user_r,
						   const char **error_r);
void mail_storage_service_restrict_setenv(struct mail_storage_service_ctx *ctx,
					  struct mail_storage_service_user *user);
/* Combine lookup() and next() into one call. */
int mail_storage_service_lookup_next(struct mail_storage_service_ctx *ctx,
				     const struct mail_storage_service_input *input,
				     struct mail_storage_service_user **user_r,
				     struct mail_user **mail_user_r,
				     const char **error_r);
void mail_storage_service_user_ref(struct mail_storage_service_user *user);
void mail_storage_service_user_unref(struct mail_storage_service_user **user);
/* Initialize iterating through all users. */
void mail_storage_service_all_init(struct mail_storage_service_ctx *ctx);
/* Initialize iterating through all users with a user mask hint to the
   userdb iteration lookup. This itself isn't yet guaranteed to filter out any
   usernames. */
void mail_storage_service_all_init_mask(struct mail_storage_service_ctx *ctx,
					const char *user_mask_hint);
/* Iterate through all usernames. Returns 1 if username was returned, 0 if
   there are no more users, -1 if error. */
int mail_storage_service_all_next(struct mail_storage_service_ctx *ctx,
				  const char **username_r);
void mail_storage_service_deinit(struct mail_storage_service_ctx **ctx);
/* Returns the first created service context. If it gets freed, NULL is
   returned until the next time mail_storage_service_init() is called. */
struct mail_storage_service_ctx *mail_storage_service_get_global(void);

/* Activate user context. Normally this is called automatically by the ioloop,
   but e.g. during loops at deinit where all users are being destroyed, it's
   useful to call this to set the correct user-specific log prefix. */
void mail_storage_service_io_activate_user(struct mail_storage_service_user *user);
/* Deactivate user context. This only switches back to non-user-specific
   log prefix. */
void mail_storage_service_io_deactivate_user(struct mail_storage_service_user *user);

/* Return the settings pointed to by set_root parameter in _init().
   The settings contain all the changes done by userdb lookups. */
void **mail_storage_service_user_get_set(struct mail_storage_service_user *user);
const struct mail_storage_settings *
mail_storage_service_user_get_mail_set(struct mail_storage_service_user *user);
const struct mail_storage_service_input *
mail_storage_service_user_get_input(struct mail_storage_service_user *user);
struct setting_parser_context *
mail_storage_service_user_get_settings_parser(struct mail_storage_service_user *user);
struct mail_storage_service_ctx *
mail_storage_service_user_get_service_ctx(struct mail_storage_service_user *user);
pool_t mail_storage_service_user_get_pool(struct mail_storage_service_user *user);

const struct var_expand_table *
mail_storage_service_get_var_expand_table(struct mail_storage_service_ctx *ctx,
					  struct mail_storage_service_input *input);
const char *mail_storage_service_fields_var_expand(const char *data,
						   const char *const *fields);
/* Return the settings pointed to by set_root parameter in _init() */
void *mail_storage_service_get_settings(struct master_service *service);
/* Updates settings for storage service user, forwards return value of settings_parse_keyvalue() */
int mail_storage_service_user_set_setting(struct mail_storage_service_user *user,
					  const char *key,
					  const char *value,
					  const char **error_r);

#endif
