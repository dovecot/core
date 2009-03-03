#ifndef COMMON_H
#define COMMON_H

struct ip_addr;

#include "lib.h"
#include "master-settings.h"

#define AUTH_SUCCESS_PATH PKG_STATEDIR"/auth-success"

extern struct ioloop *ioloop;
extern int null_fd, inetd_login_fd;
extern uid_t master_uid;
extern char program_path[];
extern char ssl_manual_key_password[];
extern const char *env_tz;
extern bool auth_success_written;
extern bool core_dumps_disabled;
#ifdef DEBUG
extern bool gdb;
#endif

#define IS_INETD() \
	(inetd_login_fd != -1)

#endif
