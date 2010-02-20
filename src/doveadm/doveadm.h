#ifndef DOVEADM_H
#define DOVEADM_H

#define USAGE_CMDNAME_FMT "  %-12s"

typedef void doveadm_command_t(int argc, char *argv[]);

struct doveadm_cmd {
	doveadm_command_t *cmd;
	const char *name;
	const char *short_usage;
	const char *long_usage;
};

extern struct doveadm_cmd doveadm_cmd_auth;
extern struct doveadm_cmd doveadm_cmd_user;
extern struct doveadm_cmd doveadm_cmd_dump;
extern struct doveadm_cmd doveadm_cmd_pw;
extern struct doveadm_cmd doveadm_cmd_who;

extern bool doveadm_verbose, doveadm_debug;

void doveadm_register_cmd(const struct doveadm_cmd *cmd);

void usage(void);
void help(const struct doveadm_cmd *cmd);

const char *unixdate2str(time_t timestamp);

#endif
