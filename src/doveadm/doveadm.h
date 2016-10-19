#ifndef DOVEADM_H
#define DOVEADM_H

#include <sysexits.h>
#include "doveadm-util.h"
#include "doveadm-cmd.h"
#include "doveadm-settings.h"

#define USAGE_CMDNAME_FMT "  %-12s"

#define DOVEADM_EX_NOTFOUND EX_NOHOST
#define DOVEADM_EX_NOTPOSSIBLE EX_DATAERR

extern bool doveadm_verbose_proctitle;
extern int doveadm_exit_code;

void usage(void) ATTR_NORETURN;
void help(const struct doveadm_cmd *cmd) ATTR_NORETURN;
void help_ver2(const struct doveadm_cmd_ver2 *cmd) ATTR_NORETURN;
void doveadm_master_send_signal(int signo);

#endif
