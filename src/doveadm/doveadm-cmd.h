#ifndef DOVEADM_CMD_H
#define DOVEADM_CMD_H

typedef void doveadm_command_t(int argc, char *argv[]);

struct doveadm_cmd {
	doveadm_command_t *cmd;
	const char *name;
	const char *short_usage;
};
ARRAY_DEFINE_TYPE(doveadm_cmd, struct doveadm_cmd);
extern ARRAY_TYPE(doveadm_cmd) doveadm_cmds;

extern struct doveadm_cmd doveadm_cmd_stop;
extern struct doveadm_cmd doveadm_cmd_reload;
extern struct doveadm_cmd doveadm_cmd_dump;
extern struct doveadm_cmd doveadm_cmd_pw;
extern struct doveadm_cmd doveadm_cmd_who;
extern struct doveadm_cmd doveadm_cmd_penalty;
extern struct doveadm_cmd doveadm_cmd_kick;
extern struct doveadm_cmd doveadm_cmd_mailbox_mutf7;
extern struct doveadm_cmd doveadm_cmd_sis_deduplicate;
extern struct doveadm_cmd doveadm_cmd_sis_find;
extern struct doveadm_cmd doveadm_cmd_stats_dump;
extern struct doveadm_cmd doveadm_cmd_stats_top;
extern struct doveadm_cmd doveadm_cmd_zlibconnect;

void doveadm_register_cmd(const struct doveadm_cmd *cmd);

const struct doveadm_cmd *
doveadm_cmd_find(const char *cmd_name, int *argc, char **argv[]);

void doveadm_register_auth_commands(void);
void doveadm_register_director_commands(void);
void doveadm_register_proxy_commands(void);
void doveadm_register_log_commands(void);
void doveadm_register_instance_commands(void);
void doveadm_register_mount_commands(void);
void doveadm_register_replicator_commands(void);
void doveadm_register_dict_commands(void);
void doveadm_register_fs_commands(void);

void doveadm_cmds_init(void);
void doveadm_cmds_deinit(void);

#endif
