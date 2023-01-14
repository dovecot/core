#ifndef DOVEADM_H
#define DOVEADM_H

#include <sysexits.h>
#include "doveadm-protocol.h"
#include "doveadm-util.h"
#include "doveadm-settings.h"

#define USAGE_CMDNAME_FMT "  %-12s"

enum doveadm_client_type {
	DOVEADM_CONNECTION_TYPE_CLI = 0,
	DOVEADM_CONNECTION_TYPE_TCP,
	DOVEADM_CONNECTION_TYPE_HTTP,
};

#include "doveadm-cmd.h"

extern bool doveadm_verbose_proctitle;
extern int doveadm_exit_code;

void usage(void) ATTR_NORETURN;
void help_ver2(const struct doveadm_cmd_ver2 *cmd) ATTR_NORETURN;
void doveadm_master_send_signal(int signo, struct event *event);
int master_service_send_cmd(const char *cmd, struct istream **input_r,
			    const char **error_r);

#endif
