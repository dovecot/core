#ifndef __AUTH_PROCESS_H
#define __AUTH_PROCESS_H

void auth_master_callback(const char *user, const char *const *args,
			  void *context);

/* Find process for given id */
struct auth_process *auth_process_find(unsigned int pid);

/* Request information about given cookie */
void auth_process_request(struct auth_process *process, unsigned int login_pid,
			  unsigned int login_id, void *context);

/* Close any fds used by auth processes */
void auth_processes_destroy_all(void);

void auth_processes_init(void);
void auth_processes_deinit(void);

#endif
