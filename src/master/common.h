#ifndef COMMON_H
#define COMMON_H

#include "lib.h"
#include "master-interface.h"
#include "master-settings.h"

extern uid_t master_uid;
extern gid_t master_gid;
extern bool core_dumps_disabled;
extern const char *ssl_manual_key_password;
extern int null_fd, global_master_dead_pipe_fd[2];
extern struct service_list *services;

void process_exec(const char *cmd, const char *extra_args[]) ATTR_NORETURN;

int get_uidgid(const char *user, uid_t *uid_r, gid_t *gid_r,
	       const char **error_r);
int get_gid(const char *group, gid_t *gid_r, const char **error_r);

#endif
