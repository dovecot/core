#ifndef MAIL_STORAGE_SERVICE_H
#define MAIL_STORAGE_SERVICE_H

#include "net.h"
#include "module-context.h"

struct master_service;
struct ssl_iostream_settings;
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
	/* Don't create namespaces, only the user. */
	MAIL_STORAGE_SERVICE_FLAG_NO_NAMESPACES		= 0x800,
	/* Initialize the user only minimally. Used by "doveadm mail fs"
	   commands. */
	MAIL_STORAGE_SERVICE_FLAG_MINIMAL_USER_INIT	= 0x1000,
};

struct mail_storage_service_input {
	struct event *event_parent;

	/* service name - NULL defaults to master_service_get_name() */
	const char *service;
	/* protocol name - defaults to service name */
	const char *protocol;
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
	const char *local_name;

	/* SETTINGS_OVERRIDE_TYPE_USERDB fields */
	const char *const *userdb_fields;
	/* SETTINGS_OVERRIDE_TYPE_CODE fields */
	const char *const *code_override_fields;

	const char *const *forward_fields;

	/* Use this settings instance instead of looking it up. */
	struct settings_instance *set_instance;

	/* Override specified global flags */
	enum mail_storage_service_flags flags_override_add;
	enum mail_storage_service_flags flags_override_remove;

	/* override MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP for this lookup */
	bool no_userdb_lookup:1;
	/* Enable auth_debug=yes for this lookup */
	bool debug:1;
	/* The end client connection (not just the previous hop proxy
	   connection) is using TLS. */
	bool end_client_tls_secured:1;
	/* User is autocreated (e.g. raw storage user) */
	bool autocreated:1;
	/* Don't free the user if user initialization fails. The caller is
	   expected to free the user. */
	bool no_free_init_failure:1;
};

struct mail_storage_service_user {
	pool_t pool;
	int refcount;

	struct mail_storage_service_ctx *service_ctx;
	struct mail_storage_service_input input;
	enum mail_storage_service_flags flags;

	struct event *event;
	struct ioloop_context *ioloop_ctx;
	const char *log_prefix, *auth_mech, *auth_token, *auth_user;
	const char *master_user;
	const char *local_name;

	const char *system_groups_user, *uid_source, *gid_source;
	const char *chdir_path;
	const struct mail_user_settings *user_set;
	struct settings_instance *set_instance;

	unsigned int session_id_counter;

	/* Module-specific contexts. See mail_storage_module_id. */
	ARRAY(union mail_storage_service_user_module_context *) module_contexts;

	bool anonymous:1;
	bool admin:1;
	bool master_service_user_set:1;
	bool home_from_userdb:1;
};

struct mail_storage_service_user_module_register {
	unsigned int id;
};

union mail_storage_service_user_module_context {
	struct mail_storage_service_user_module_register *reg;
};
extern struct mail_storage_service_user_module_register
	mail_storage_service_user_module_register;
extern struct module *mail_storage_service_modules;

/* Stored here, since it's used by both obox and fts_dovecot plugins.
   It's better not to have to link fts_dovecot with obox plugin. */
extern MODULE_CONTEXT_DEFINE(metacache_service_user_module,
			     &mail_storage_service_user_module_register);

struct mail_storage_service_ctx *
mail_storage_service_init(struct master_service *service,
			  enum mail_storage_service_flags flags);
struct auth_master_connection *
mail_storage_service_get_auth_conn(struct mail_storage_service_ctx *ctx);
/* Set auth connection (instead of creating a new one automatically). */
void mail_storage_service_set_auth_conn(struct mail_storage_service_ctx *ctx,
					struct auth_master_connection *conn);
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
void mail_storage_service_restrict_setenv(struct mail_storage_service_user *user);
/* Combine lookup() and next() into one call. */
int mail_storage_service_lookup_next(struct mail_storage_service_ctx *ctx,
				     const struct mail_storage_service_input *input,
				     struct mail_user **mail_user_r,
				     const char **error_r);
void mail_storage_service_user_ref(struct mail_storage_service_user *user);
void mail_storage_service_user_unref(struct mail_storage_service_user **user);
/* Duplicate service user. It still uses the same memory pool as the original
   user. */
struct mail_storage_service_user *
mail_storage_service_user_dup(const struct mail_storage_service_user *user);
/* Return userdb fields for the user. */
const char *const *
mail_storage_service_user_get_userdb_fields(struct mail_storage_service_user *user);
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

/* Activate user context. Normally this is called automatically by the ioloop,
   but e.g. during loops at deinit where all users are being destroyed, it's
   useful to call this to set the correct user-specific log prefix. */
void mail_storage_service_io_activate_user(struct mail_storage_service_user *user);
/* Deactivate user context. This only switches back to non-user-specific
   log prefix. */
void mail_storage_service_io_deactivate_user(struct mail_storage_service_user *user);

/* Return the user settings. They contain all the changes done by userdb
   lookups. */
const struct mail_user_settings *
mail_storage_service_user_get_set(struct mail_storage_service_user *user);
const struct mail_storage_service_input *
mail_storage_service_user_get_input(struct mail_storage_service_user *user);
struct settings_instance *
mail_storage_service_user_get_settings_instance(struct mail_storage_service_user *user);
struct mail_storage_service_ctx *
mail_storage_service_user_get_service_ctx(struct mail_storage_service_user *user);
pool_t mail_storage_service_user_get_pool(struct mail_storage_service_user *user);
const char *
mail_storage_service_user_get_log_prefix(struct mail_storage_service_user *user);
struct event *
mail_storage_service_user_get_event(const struct mail_storage_service_user *user);
const char *
mail_storage_service_user_get_username(const struct mail_storage_service_user *user);

const char *
mail_storage_service_get_log_prefix(struct mail_storage_service_ctx *ctx);
enum mail_storage_service_flags
mail_storage_service_get_flags(struct mail_storage_service_ctx *ctx);

const struct var_expand_params *
mail_storage_service_get_var_expand_params(struct mail_storage_service_ctx *ctx,
					   struct mail_storage_service_input *input);
const char *mail_storage_service_fields_var_expand(const char *data,
						   const char *const *fields);
void mail_storage_service_restore_privileges(uid_t old_uid, const char *old_cwd,
					     struct event *event);

#endif
