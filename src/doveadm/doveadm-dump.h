#ifndef DOVEADM_DUMP_H
#define DOVEADM_DUMP_H

#include "doveadm.h"

struct doveadm_cmd_dump {
	const char *name;
	bool (*test)(const char *path);
	doveadm_command_t *cmd;
};

extern struct doveadm_cmd_dump doveadm_cmd_dump_index;
extern struct doveadm_cmd_dump doveadm_cmd_dump_log;
extern struct doveadm_cmd_dump doveadm_cmd_dump_mailboxlog;
extern struct doveadm_cmd_dump doveadm_cmd_dump_thread;

#endif
