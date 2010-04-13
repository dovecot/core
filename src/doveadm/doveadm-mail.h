#ifndef DOVEADM_MAIL_H
#define DOVEADM_MAIL_H

struct mail_user;

typedef void doveadm_mail_command_t(struct mail_user *mail_user,
				    const char *const args[]);

struct doveadm_mail_cmd {
	doveadm_mail_command_t *cmd;
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

void doveadm_mail_init(void);
void doveadm_mail_deinit(void);

struct mailbox *
doveadm_mailbox_find_and_sync(struct mail_user *user, const char *mailbox);

void cmd_fetch(struct mail_user *user, const char *const args[]);

#endif
