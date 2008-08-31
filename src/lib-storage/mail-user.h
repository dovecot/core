#ifndef MAIL_USER_H
#define MAIL_USER_H

struct mail_user;

struct mail_user_vfuncs {
	void (*deinit)(struct mail_user *user);
};

struct mail_user {
	pool_t pool;
	struct mail_user_vfuncs v;

	const char *username;
	const char *home;

	struct mail_namespace *namespaces;

	/* Module-specific contexts. See mail_storage_module_id. */
	ARRAY_DEFINE(module_contexts, union mail_user_module_context *);
};

struct mail_user_module_register {
	unsigned int id;
};

union mail_user_module_context {
	struct mail_user_vfuncs super;
	struct mail_user_module_register *reg;
};
extern struct mail_user_module_register mail_user_module_register;

/* Called after user has been created */
extern void (*hook_mail_user_created)(struct mail_user *user);

struct mail_user *mail_user_init(const char *username, const char *home);
void mail_user_deinit(struct mail_user **user);

/* Replace ~/ at the beginning of the path with the user's home directory. */
const char *mail_user_home_expand(struct mail_user *user, const char *path);
/* Returns 0 if ok, -1 if home directory isn't set. */
int mail_user_try_home_expand(struct mail_user *user, const char **path);

#endif
