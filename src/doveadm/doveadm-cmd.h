#ifndef DOVEADM_CMD_H
#define DOVEADM_CMD_H

#include "doveadm-cmd-parse.h"

typedef void doveadm_command_t(int argc, char *argv[]);

ARRAY_DEFINE_TYPE(doveadm_cmd_ver2, struct doveadm_cmd_ver2);
extern ARRAY_TYPE(doveadm_cmd_ver2) doveadm_cmds_ver2;

void doveadm_register_auth_commands(void);
void doveadm_register_auth_server_commands(void);
void doveadm_register_log_commands(void);
void doveadm_register_instance_commands(void);
void doveadm_register_mount_commands(void);
void doveadm_register_replicator_commands(void);
void doveadm_register_dict_commands(void);
void doveadm_register_fs_commands(void);

void doveadm_cmds_init(void);
void doveadm_cmds_deinit(void);

const char *const *
doveadm_cmdv2_wrapper_generate_args(struct doveadm_mail_cmd_context *ctx);
void doveadm_cmd_ver2_to_mail_cmd_wrapper(struct doveadm_cmd_context *cctx);

void doveadm_cmd_register_ver2(struct doveadm_cmd_ver2 *cmd);
const struct doveadm_cmd_ver2 *
doveadm_cmdline_find_with_args(const char *cmd_name, int *argc,
			       const char *const *argv[]);
const struct doveadm_cmd_ver2 *doveadm_cmd_find_ver2(const char *cmd_name);
/* Returns FALSE if cmd_name doesn't exist, TRUE if it exists. */
bool doveadm_cmdline_try_run(const char *cmd_name,
			     int argc, const char *const argv[],
			     struct doveadm_cmd_context *cctx);

extern struct doveadm_cmd_ver2 doveadm_cmd_dump;
extern struct doveadm_cmd_ver2 doveadm_cmd_service_stop_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_service_status_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_process_status_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_stop_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_reload_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_stats_dump_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_stats_add_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_stats_remove_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_mailbox_mutf7;
extern struct doveadm_cmd_ver2 doveadm_cmd_penalty_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_pw;
extern struct doveadm_cmd_ver2 doveadm_cmd_kick_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_proxy_kick_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_who_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_proxy_list_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_sis_deduplicate;
extern struct doveadm_cmd_ver2 doveadm_cmd_sis_find;
extern struct doveadm_cmd_ver2 doveadm_cmd_compress_connect;
extern struct doveadm_cmd_ver2 doveadm_cmd_indexer_add;
extern struct doveadm_cmd_ver2 doveadm_cmd_indexer_remove;
extern struct doveadm_cmd_ver2 doveadm_cmd_indexer_list;

#endif
