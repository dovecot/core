#ifndef DOVEADM_CMD_H
#define DOVEADM_CMD_H

#include "net.h"

#define DOVEADM_CMD_PARAMS_START .parameters = (const struct doveadm_cmd_param[]){
#define DOVEADM_CMD_PARAM(optP, nameP, typeP, flagP ) { .short_opt = optP, .name = nameP, .type = typeP, .flags = flagP },
#define DOVEADM_CMD_PARAMS_END { .short_opt = '\0', .name = NULL, .type = CMD_PARAM_BOOL, .flags = CMD_PARAM_FLAG_NONE } }

struct doveadm_cmd_ver2;
struct doveadm_cmd_context;
struct doveadm_mail_cmd_context;

typedef void doveadm_command_t(int argc, char *argv[]);

typedef enum {
	CMD_PARAM_BOOL = 0, /* value will contain 1 (not pointer) */
	CMD_PARAM_INT64,    /* ditto but contains number (not pointer) */
	CMD_PARAM_IP,	   /* value contains struct ip_addr */
	CMD_PARAM_STR,     /* value contains const char* */
	CMD_PARAM_ARRAY,   /* value contains const char*[] */
	CMD_PARAM_ISTREAM  /* value contains struct istream* */
} doveadm_cmd_param_t;

typedef enum {
	CMD_PARAM_FLAG_NONE		= 0x0,
	CMD_PARAM_FLAG_POSITIONAL 	= 0x1,
	CMD_PARAM_FLAG_DO_NOT_EXPOSE	= 0x2,
} doveadm_cmd_param_flag_t;

typedef enum {
	CMD_FLAG_NONE			= 0x0,
	CMD_FLAG_HIDDEN			= 0x1,
	CMD_FLAG_NO_PRINT		= 0x2,
} doveadm_cmd_flag_t;

struct doveadm_cmd_param {
	char short_opt;
	const char *name;
	doveadm_cmd_param_t type;
	bool value_set;
	struct {
		bool v_bool;
		int64_t v_int64;
		const char* v_string;
		ARRAY_TYPE(const_string) v_array;
		struct ip_addr v_ip;
		struct istream* v_istream;
	} value;
	doveadm_cmd_param_flag_t flags;
};
ARRAY_DEFINE_TYPE(doveadm_cmd_param_arr_t, struct doveadm_cmd_param);

typedef void doveadm_command_ver2_t(struct doveadm_cmd_context *cctx);

struct doveadm_cmd {
	doveadm_command_t *cmd;
	const char *name;
	const char *short_usage;
};

struct doveadm_cmd_ver2 {
	doveadm_command_ver2_t *cmd;
	doveadm_command_t *old_cmd;
	struct doveadm_mail_cmd_context *(*mail_cmd)(void);
	const char *name;
	const char *usage;
	doveadm_cmd_flag_t flags;
	const struct doveadm_cmd_param *parameters;
};

struct doveadm_cmd_context {
	const struct doveadm_cmd_ver2 *cmd; /* for help */

	int argc;
	const struct doveadm_cmd_param *argv;

	const char *username;
	bool cli;
	struct ip_addr local_ip, remote_ip;
	in_port_t local_port, remote_port;
};

ARRAY_DEFINE_TYPE(doveadm_cmd, struct doveadm_cmd);
extern ARRAY_TYPE(doveadm_cmd) doveadm_cmds;

ARRAY_DEFINE_TYPE(doveadm_cmd_ver2, struct doveadm_cmd_ver2);
extern ARRAY_TYPE(doveadm_cmd_ver2) doveadm_cmds_ver2;

extern struct doveadm_cmd doveadm_cmd_dump;
extern struct doveadm_cmd doveadm_cmd_pw;
extern struct doveadm_cmd doveadm_cmd_mailbox_mutf7;
extern struct doveadm_cmd doveadm_cmd_sis_deduplicate;
extern struct doveadm_cmd doveadm_cmd_sis_find;
extern struct doveadm_cmd doveadm_cmd_zlibconnect;

void doveadm_register_cmd(const struct doveadm_cmd *cmd);

const struct doveadm_cmd *
doveadm_cmd_find_with_args(const char *cmd_name, int *argc,
			   const char *const *argv[]);

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

void doveadm_cmd_ver2_to_cmd_wrapper(struct doveadm_cmd_context *cctx);
void doveadm_cmd_ver2_to_mail_cmd_wrapper(struct doveadm_cmd_context *cctx);

void doveadm_cmd_register_ver2(struct doveadm_cmd_ver2 *cmd);
const struct doveadm_cmd_ver2 *
doveadm_cmd_find_with_args_ver2(const char *cmd_name, int *argc,
				const char *const *argv[]);
const struct doveadm_cmd_ver2 *doveadm_cmd_find_ver2(const char *cmd_name);
/* Returns FALSE if cmd_name doesn't exist, TRUE if it exists. */
bool doveadm_cmd_try_run_ver2(const char *cmd_name,
	int argc, const char *const argv[],
	struct doveadm_cmd_context *cctx);
/* Returns 0 if success, -1 if parameters were invalid. */
int doveadm_cmd_run_ver2(int argc, const char *const argv[],
	struct doveadm_cmd_context *cctx);

bool doveadm_cmd_param_bool(const struct doveadm_cmd_context *cctx,
			    const char *name, bool *value_r);
bool doveadm_cmd_param_int64(const struct doveadm_cmd_context *cctx,
			     const char *name, int64_t *value_r);
bool doveadm_cmd_param_str(const struct doveadm_cmd_context *cctx,
			   const char *name, const char **value_r);
bool doveadm_cmd_param_ip(const struct doveadm_cmd_context *cctx,
			  const char *name, struct ip_addr *value_r);
bool doveadm_cmd_param_array(const struct doveadm_cmd_context *cctx,
			     const char *name, const char *const **value_r);
bool doveadm_cmd_param_istream(const struct doveadm_cmd_context *cctx,
			       const char *name, struct istream **value_r);

void doveadm_cmd_params_clean(ARRAY_TYPE(doveadm_cmd_param_arr_t) *pargv);
void doveadm_cmd_params_null_terminate_arrays(ARRAY_TYPE(doveadm_cmd_param_arr_t) *pargv);

extern struct doveadm_cmd_ver2 doveadm_cmd_stop_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_reload_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_stats_reset_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_stats_dump_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_stats_top_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_penalty_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_kick_ver2;
extern struct doveadm_cmd_ver2 doveadm_cmd_who_ver2;

#endif
