#ifndef DOVEADM_H
#define DOVEADM_H

#include <sysexits.h>
#include "doveadm-util.h"
#include "doveadm-settings.h"

#define USAGE_CMDNAME_FMT "  %-12s"

#define DOVEADM_EX_NOTFOUND EX_NOHOST
#define DOVEADM_EX_NOTPOSSIBLE EX_DATAERR
#define DOVEADM_EX_UNKNOWN -1

#define DOVEADM_EX_NOREPLICATE 1001

enum doveadm_client_type {
	DOVEADM_CONNECTION_TYPE_CLI = 0,
	DOVEADM_CONNECTION_TYPE_TCP,
	DOVEADM_CONNECTION_TYPE_HTTP,
};

#include "doveadm-cmd.h"

extern bool doveadm_verbose_proctitle;
extern int doveadm_exit_code;

void usage(void) ATTR_NORETURN;
void help(const struct doveadm_cmd *cmd) ATTR_NORETURN;
void help_ver2(const struct doveadm_cmd_ver2 *cmd) ATTR_NORETURN;
void doveadm_master_send_signal(int signo);

const char *doveadm_exit_code_to_str(int code);
int doveadm_str_to_exit_code(const char *reason);

#endif
