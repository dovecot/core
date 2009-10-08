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

extern struct doveadm_cmd doveadm_cmd_pw;

void doveadm_register_cmd(const struct doveadm_cmd *cmd);

void usage(void);
void help(const struct doveadm_cmd *cmd);

#endif
