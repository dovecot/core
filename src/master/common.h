#ifndef COMMON_H
#define COMMON_H

#include "lib.h"
#include "master-interface.h"
#include "master-settings.h"

extern struct master_service *master_service;
extern uid_t master_uid;
extern gid_t master_gid;
extern bool core_dumps_disabled;
extern int null_fd;

void process_exec(const char *cmd, const char *extra_args[]) ATTR_NORETURN;

#endif
