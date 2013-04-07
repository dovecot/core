#ifndef DOVEADM_H
#define DOVEADM_H

#include <sysexits.h>
#include "doveadm-util.h"
#include "doveadm-settings.h"

#define USAGE_CMDNAME_FMT "  %-12s"

#define DOVEADM_EX_NOTFOUND EX_NOHOST
#define DOVEADM_EX_NOTPOSSIBLE EX_DATAERR

typedef void doveadm_command_t(int argc, char *argv[]);

struct doveadm_cmd {
	doveadm_command_t *cmd;
	const char *name;
	const char *short_usage;
};

extern int doveadm_exit_code;

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

void usage(void) ATTR_NORETURN;
void help(const struct doveadm_cmd *cmd) ATTR_NORETURN;
void doveadm_master_send_signal(int signo);

void doveadm_register_auth_commands(void);
void doveadm_register_director_commands(void);
void doveadm_register_proxy_commands(void);
void doveadm_register_log_commands(void);
void doveadm_register_instance_commands(void);
void doveadm_register_mount_commands(void);
void doveadm_register_replicator_commands(void);
void doveadm_register_fs_commands(void);

#endif
