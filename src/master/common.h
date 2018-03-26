#ifndef COMMON_H
#define COMMON_H

#include "lib.h"
#include "master-interface.h"
#include "master-settings.h"

#define LINUX_PROC_FS_SUID_DUMPABLE "/proc/sys/fs/suid_dumpable"
#define LINUX_PROC_SYS_KERNEL_CORE_PATTERN "/proc/sys/kernel/core_pattern"

extern uid_t master_uid;
extern gid_t master_gid;
extern bool core_dumps_disabled;
extern bool have_proc_fs_suid_dumpable;
extern bool have_proc_sys_kernel_core_pattern;
extern const char *ssl_manual_key_password;
extern int global_master_dead_pipe_fd[2];
extern struct service_list *services;
extern bool startup_finished;

void process_exec(const char *cmd) ATTR_NORETURN;

int get_uidgid(const char *user, uid_t *uid_r, gid_t *gid_r,
	       const char **error_r);
int get_gid(const char *group, gid_t *gid_r, const char **error_r);

#endif
