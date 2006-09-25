#ifndef __LOGIN_PROCESS_H
#define __LOGIN_PROCESS_H

struct login_group {
	struct login_group *next;
	int refcount;

	enum process_type process_type;
	struct settings *set;

	unsigned int processes;
	unsigned int listening_processes;
	unsigned int wanted_processes_count;

	/* if login_process_per_connection=yes this contains the list of
	   processes that are in LOGIN_STATE_FULL_PRELOGINS state */
	struct login_process *oldest_prelogin_process;
	struct login_process *newest_prelogin_process;
};

void login_process_destroyed(pid_t pid, bool abnormal_exit);

void login_processes_destroy_all(bool unref);

void login_processes_init(void);
void login_processes_deinit(void);

#endif
