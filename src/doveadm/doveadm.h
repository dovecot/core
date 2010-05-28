#ifndef DOVEADM_H
#define DOVEADM_H

#include "doveadm-settings.h"

#define USAGE_CMDNAME_FMT "  %-12s"

typedef void doveadm_command_t(int argc, char *argv[]);

struct doveadm_cmd {
	doveadm_command_t *cmd;
	const char *name;
	const char *short_usage;
	const char *long_usage;
};

extern struct doveadm_cmd doveadm_cmd_stop;
extern struct doveadm_cmd doveadm_cmd_reload;
extern struct doveadm_cmd doveadm_cmd_auth;
extern struct doveadm_cmd doveadm_cmd_user;
extern struct doveadm_cmd doveadm_cmd_dump;
extern struct doveadm_cmd doveadm_cmd_pw;
extern struct doveadm_cmd doveadm_cmd_who;
extern struct doveadm_cmd doveadm_cmd_penalty;
extern struct doveadm_cmd doveadm_cmd_kick;
extern struct doveadm_cmd doveadm_cmd_mailbox_convert;

extern bool doveadm_verbose, doveadm_debug;

void doveadm_register_cmd(const struct doveadm_cmd *cmd);

void usage(void) ATTR_NORETURN;
void help(const struct doveadm_cmd *cmd);

const char *unixdate2str(time_t timestamp);
const char *doveadm_plugin_getenv(const char *name);
void doveadm_register_director_commands(void);

#endif
