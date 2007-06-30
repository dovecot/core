#ifndef __COMMON_H
#define __COMMON_H

struct ip_addr;

#include "lib.h"
#include "master-settings.h"

extern struct ioloop *ioloop;
extern int null_fd, inetd_login_fd;
extern uid_t master_uid;
extern char program_path[];
extern char ssl_manual_key_password[];
extern const char *env_tz;
#ifdef DEBUG
extern bool gdb;
#endif

#define IS_INETD() \
	(inetd_login_fd != -1)

#endif
