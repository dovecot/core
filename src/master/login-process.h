#ifndef __LOGIN_PROCESS_H
#define __LOGIN_PROCESS_H

struct login_group {
	struct login_group *next;

	int process_type;
	struct settings *set;

	unsigned int processes;
	unsigned int listening_processes;
	unsigned int wanted_processes_count;

	struct login_process *oldest_nonlisten_process;
	struct login_process *newest_nonlisten_process;
};

void login_process_abormal_exit(pid_t pid);
void login_processes_destroy_all(void);

void login_processes_init(void);
void login_processes_deinit(void);

#endif
