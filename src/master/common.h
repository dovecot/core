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

	PROCESS_TYPE_MAX
};

const char *process_type_names[PROCESS_TYPE_MAX];

extern HashTable *pids;
extern int null_fd, imap_fd, imaps_fd;

/* processes */
#define PID_GET_PROCESS_TYPE(pid) \
	POINTER_TO_INT(hash_lookup(pids, INT_TO_POINTER(pid)))

#define PID_ADD_PROCESS_TYPE(pid, type) \
	hash_insert(pids, INT_TO_POINTER(pid), INT_TO_POINTER(type))

#define PID_REMOVE_PROCESS_TYPE(pid) \
	hash_remove(pids, INT_TO_POINTER(pid))

void clean_child_process(void);

MasterReplyResult
create_imap_process(int socket, const char *user, uid_t uid, gid_t gid,
		    const char *home, int chroot, const char *env[]);
void imap_process_destroyed(pid_t pid);

/* misc */
#define VALIDATE_STR(str) \
	validate_str(str, sizeof(str))
int validate_str(const char *str, int max_len);

#endif
