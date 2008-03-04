#ifndef CHILD_PROCESS_H
#define CHILD_PROCESS_H

enum process_type {
	PROCESS_TYPE_UNKNOWN,
	PROCESS_TYPE_AUTH,
	PROCESS_TYPE_AUTH_WORKER,
	PROCESS_TYPE_LOGIN,
	PROCESS_TYPE_IMAP,
	PROCESS_TYPE_POP3,
	PROCESS_TYPE_SSL_PARAM,
	PROCESS_TYPE_DICT,

	PROCESS_TYPE_MAX
};

struct child_process {
	enum process_type type;

	unsigned int seen_fatal:1;
};

typedef void child_process_destroy_callback_t(struct child_process *process,
					      pid_t pid, bool abnormal_exit);

extern const char *process_names[];
extern struct hash_table *processes;

struct child_process *child_process_lookup(pid_t pid);
void child_process_add(pid_t pid, struct child_process *process);
void child_process_remove(pid_t pid);

void child_process_init_env(void);
void client_process_exec(const char *cmd, const char *title);
void client_process_exec_argv(const char *executable, const char **argv);

void child_process_set_destroy_callback(enum process_type type,
					child_process_destroy_callback_t *cb);

void child_processes_init(void);
void child_processes_deinit(void);

#endif
