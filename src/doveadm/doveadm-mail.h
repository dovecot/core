#ifndef DOVEADM_MAIL_H
#define DOVEADM_MAIL_H

#include "doveadm.h"

struct mail_user;
struct doveadm_mail_cmd_context;

struct doveadm_mail_cmd_context {
	pool_t pool;

	void (*run)(struct doveadm_mail_cmd_context *ctx,
		    struct mail_user *mail_user);
	void (*deinit)(struct doveadm_mail_cmd_context *ctx);
};

struct doveadm_mail_cmd {
	struct doveadm_mail_cmd_context *
		(*init)(const char *const args[]);
	const char *name;
	const char *usage_args;
};
ARRAY_DEFINE_TYPE(doveadm_mail_cmd, struct doveadm_mail_cmd);

extern ARRAY_TYPE(doveadm_mail_cmd) doveadm_mail_cmds;

bool doveadm_mail_try_run(const char *cmd_name, int argc, char *argv[]);
void doveadm_mail_register_cmd(const struct doveadm_mail_cmd *cmd);

void doveadm_mail_usage(void);
void doveadm_mail_help(const struct doveadm_mail_cmd *cmd) ATTR_NORETURN;
void doveadm_mail_help_name(const char *cmd_name) ATTR_NORETURN;
void doveadm_mail_try_help_name(const char *cmd_name);

void doveadm_mail_init(void);
void doveadm_mail_deinit(void);

struct mailbox *
doveadm_mailbox_find_and_sync(struct mail_user *user, const char *mailbox);
struct mail_search_args *
doveadm_mail_build_search_args(const char *const args[]);

struct doveadm_mail_cmd_context *
doveadm_mail_cmd_init_size(size_t size);
#define doveadm_mail_cmd_init(type) \
	(type *)doveadm_mail_cmd_init_size(sizeof(type))

struct doveadm_mail_cmd_context *cmd_expunge(const char *const args[]);
struct doveadm_mail_cmd_context *cmd_search(const char *const args[]);
struct doveadm_mail_cmd_context *cmd_fetch(const char *const args[]);
struct doveadm_mail_cmd_context *cmd_altmove(const char *const args[]);
struct doveadm_mail_cmd_context *cmd_mailbox_list(const char *const args[]);
struct doveadm_mail_cmd_context *cmd_mailbox_create(const char *const args[]);
struct doveadm_mail_cmd_context *cmd_mailbox_delete(const char *const args[]);
struct doveadm_mail_cmd_context *cmd_mailbox_rename(const char *const args[]);

#endif
