#ifndef MAIL_USER_H
#define MAIL_USER_H

struct stats;

extern struct mail_user *stable_mail_users;

struct mail_user *mail_user_login(const char *username);
void mail_user_disconnected(struct mail_user *user);
struct mail_user *mail_user_lookup(const char *username);

void mail_user_refresh(struct mail_user *user,
		       const struct stats *diff_stats) ATTR_NULL(2);
int mail_user_add_parse(const char *const *args, const char **error_r);

void mail_user_ref(struct mail_user *user);
void mail_user_unref(struct mail_user **user);

void mail_users_free_memory(void);
void mail_users_init(void);
void mail_users_deinit(void);

#endif
