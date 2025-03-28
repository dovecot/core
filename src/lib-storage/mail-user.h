#ifndef MAIL_USER_H
#define MAIL_USER_H

#include "net.h"
#include "unichar.h"
#include "mail-storage-settings.h"
#include "process-stat.h"

#define SETTINGS_EVENT_MAIL_USER "mail_user"

struct module;
struct fs_parameters;
struct ssl_iostream_settings;
struct master_service_anvil_session;
struct mail_user;
struct dict_op_settings;

struct mail_user_vfuncs {
	void (*deinit)(struct mail_user *user);
	void (*deinit_pre)(struct mail_user *user);
};

struct mail_user_connection_data {
	struct ip_addr *local_ip, *remote_ip;
	in_port_t local_port, remote_port;
	const char *local_name;

	bool end_client_tls_secured:1;
};

struct mail_user {
	pool_t pool;
	struct mail_user_vfuncs v, *vlast;
	int refcount;

	struct event *event;
	/* User's creator if such exists. For example for autocreated shared
	   mailbox users their creator is the logged in user. */
	struct mail_user *creator;
	struct mail_storage_service_user *service_user;

	const char *username;
	/* don't access the home directly. It may be set lazily. */
	const char *_home;

	uid_t uid;
	gid_t gid;
	const char *service;
	const char *protocol;
	const char *session_id;
	struct mail_user_connection_data conn;
	const char *auth_mech, *auth_token, *auth_user;
	const char *master_user;
	const char *const *userdb_fields;
	const char *const *_alt_usernames;
	/* Timestamp when this session was initially created. Most importantly
	   this stays the same after IMAP client is hibernated and restored. */
	time_t session_create_time;

	const struct var_expand_params *var_expand_params;
	/* If non-NULL, fail the user initialization with this error.
	   This could be set by plugins that need to fail the initialization. */
	const char *error;

	const struct mail_user_settings *set;
	struct mail_namespace *namespaces;
	struct mail_storage *storages;
	struct dict_op_settings *dict_op_set;
	ARRAY(const struct mail_storage_hooks *) hooks;

	normalizer_func_t *default_normalizer;
	/* Filled lazily by mailbox_attribute_*() when accessing attributes. */
	struct dict *_attr_dict;

	/* Module-specific contexts. See mail_storage_module_id. */
	ARRAY(union mail_user_module_context *) module_contexts;

	struct process_stat proc_stat;

	/* User doesn't exist (as reported by userdb lookup when looking
	   up home) */
	bool nonexistent:1;
	/* Either home is set or there is no home for the user. */
	bool home_looked_up:1;
	/* User is anonymous */
	bool anonymous:1;
	/* This is an autocreated user (e.g. for shared namespace or
	   lda raw storage) */
	bool autocreated:1;
	/* mail_user_init() has been called */
	bool initialized:1;
	/* The initial namespaces have been created and
	   hook_mail_namespaces_created() has been called. */
	bool namespaces_created:1;
	/* If INBOX can't be opened, log an error, but only once. */
	bool inbox_open_error_logged:1;
	/* Fuzzy search works for this user (FTS enabled) */
	bool fuzzy_search:1;
	/* We're running dsync */
	bool dsyncing:1;
	/* Failed to create attribute dict, don't try again */
	bool attr_dict_failed:1;
	/* We're deinitializing the user */
	bool deinitializing:1;
	/* Enable administrator user commands for the user */
	bool admin:1;
	/* Enable all statistics gathering */
	bool stats_enabled:1;
	/* This session was restored (e.g. IMAP unhibernation) */
	bool session_restored:1;
};

struct mail_user_module_register {
	unsigned int id;
};

union mail_user_module_context {
	struct mail_user_vfuncs super;
	struct mail_user_module_register *reg;
};
extern struct mail_user_module_register mail_user_module_register;
extern struct auth_master_connection *mail_user_auth_master_conn;
extern const struct var_expand_provider *mail_user_var_expand_providers;

struct mail_user *
mail_user_alloc(struct mail_storage_service_user *service_user);
/* Returns -1 if settings were invalid. */
int mail_user_init(struct mail_user *user, const char **error_r);

void mail_user_ref(struct mail_user *user);
void mail_user_unref(struct mail_user **user);
/* Assert that this is the last reference for the user and unref it. */
void mail_user_deinit(struct mail_user **user);

/* Duplicate a mail_user. mail_user_init() and mail_namespaces_init() need to
   be called before the user is usable. */
struct mail_user *mail_user_dup(struct mail_user *user);

/* Find another user from the given user's namespaces. */
struct mail_user *mail_user_find(struct mail_user *user, const char *name);

/* Specify mail location %variable expansion data. */
void mail_user_set_vars(struct mail_user *user, const char *service,
			const struct mail_user_connection_data *conn);
/* Return %variable expansion table for the user. */
const struct var_expand_params *
mail_user_var_expand_params(struct mail_user *user);

/* Specify the user's home directory. This should be called also with home=NULL
   when it's known that the user doesn't have a home directory to avoid the
   internal lookup. */
void mail_user_set_home(struct mail_user *user, const char *home);
/* Get the home directory for the user. Returns 1 if home directory looked up
   successfully, 0 if there is no home directory (either user doesn't exist or
   has no home directory) or -1 if lookup failed. The returned home string
   is valid until the user is freed. */
int mail_user_get_home(struct mail_user *user, const char **home_r);
/* Appends path + file prefix for creating a temporary file.
   The file prefix doesn't contain any uniqueness. */
void mail_user_set_get_temp_prefix(string_t *dest,
				   const struct mail_user_settings *set);
/* Get volatile directory from INBOX namespace if configured. Returns NULL if
   none is configured. */
const char *mail_user_get_volatile_dir(struct mail_user *user);
/* Returns 1 on success, 0 if lock_secs is reached, -1 on error */
int mail_user_lock_file_create(struct mail_user *user, const char *lock_fname,
			       unsigned int lock_secs,
			       struct file_lock **lock_r, const char **error_r);

/* Returns TRUE if plugin is loaded for the user. */
bool mail_user_is_plugin_loaded(struct mail_user *user, struct module *module);

/* Add more namespaces to user's namespaces. The ->next pointers may be
   changed, so the namespaces pointer will be updated to user->namespaces. */
void mail_user_add_namespace(struct mail_user *user,
			     struct mail_namespace **namespaces);
/* Drop autocreated shared namespaces that don't have any "usable" mailboxes. */
void mail_user_drop_useless_namespaces(struct mail_user *user);

/* Replace ~/ at the beginning of the path with the user's home directory. */
const char *mail_user_home_expand(struct mail_user *user, const char *path);
/* Returns 0 if ok, -1 if home directory isn't set. */
int mail_user_try_home_expand(struct mail_user *user, const char **path);
/* Fill out anvil session struct for the user session. */
void mail_user_get_anvil_session(struct mail_user *user,
				 struct master_service_anvil_session *session_r);
/* Returns NULL-terminated array of (user_field, value) pairs. The fields are
   extracted from user->userdb_fields[]. */
const char *const *mail_user_get_alt_usernames(struct mail_user *user);

/* Basically the same as mail_storage_find_class(), except automatically load
   storage plugins when needed. */
struct mail_storage *
mail_user_get_storage_class(struct mail_user *user, const char *name);

/* Import any event_ fields from userdb fields to mail user event. */
void mail_user_add_event_fields(struct mail_user *user);

/* Initialize fs_parameters from mail_user settings. */
void mail_user_init_fs_parameters(struct mail_user *user,
				struct fs_parameters *fs_set);

/* Try to mkdir() user's home directory. Ideally this should be called only
   after the caller tries to create a file to the home directory, but it fails
   with ENOENT. This way it avoids unnecessary disk IO to the home. */
int mail_user_home_mkdir(struct mail_user *user);

/* Return dict_op_settings for the user. The returned settings are valid until
   the user is freed. */
const struct dict_op_settings *
mail_user_get_dict_op_settings(struct mail_user *user);


/* Obtain the postmaster address to be used for this user as an RFC 5322 (IMF)
   address. Returns false if the configured postmaster address is invalid in
   which case error_r contains the error message. */
static inline bool
mail_user_get_postmaster_address(struct mail_user *user,
				 const struct message_address **address_r,
				 const char **error_r)
{
	return mail_user_set_get_postmaster_address(user->set, address_r,
						    error_r);
}

/* Obtain the postmaster address to be used for this user as an RFC 5321 (SMTP)
   address. Returns false if the configured postmaster address is invalid in
   which case error_r contains the error message. */
static inline bool
mail_user_get_postmaster_smtp(struct mail_user *user,
			      const struct smtp_address **address_r,
			      const char **error_r)
{
	return mail_user_set_get_postmaster_smtp(user->set, address_r,
						 error_r);
}

#endif
