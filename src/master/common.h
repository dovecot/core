#ifndef __COMMON_H
#define __COMMON_H

#include "lib.h"
#include "hash.h"
#include "settings.h"

#include "../auth/auth-interface.h"
#include "master-interface.h"

enum {
	PROCESS_TYPE_UNKNOWN,
	PROCESS_TYPE_AUTH,
	PROCESS_TYPE_LOGIN,
	PROCESS_TYPE_IMAP,
	PROCESS_TYPE_SSL_PARAM,

	PROCESS_TYPE_MAX
};

extern struct hash_table *pids;
extern int null_fd, imap_fd, imaps_fd;

/* processes */
#define PID_GET_PROCESS_TYPE(pid) \
	POINTER_CAST_TO(hash_lookup(pids, POINTER_CAST(pid)), pid_t)

#define PID_ADD_PROCESS_TYPE(pid, type) \
	hash_insert(pids, POINTER_CAST(pid), POINTER_CAST(type))

#define PID_REMOVE_PROCESS_TYPE(pid) \
	hash_remove(pids, POINTER_CAST(pid))

void clean_child_process(void);

enum master_reply_result
create_imap_process(int socket, struct ip_addr *ip,
		    const char *system_user, const char *virtual_user,
		    uid_t uid, gid_t gid, const char *home, int chroot,
		    const char *mail, const char *login_tag);
void imap_process_destroyed(pid_t pid);

/* misc */
#define VALIDATE_STR(str) \
	validate_str(str, sizeof(str))
int validate_str(const char *str, size_t max_len);

#endif
