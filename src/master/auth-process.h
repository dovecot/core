#ifndef __AUTH_PROCESS_H
#define __AUTH_PROCESS_H

struct login_auth_request;

extern bool have_initialized_auth_processes;

void auth_master_callback(const char *user, const char *const *args,
			  struct login_auth_request *request);

/* Find process for given id */
struct auth_process *auth_process_find(unsigned int pid);

/* Request information about given cookie */
void auth_process_request(struct auth_process *process, unsigned int login_pid,
			  unsigned int login_id,
			  struct login_auth_request *request);

/* Close any fds used by auth processes */
void auth_processes_destroy_all(void);

void auth_processes_init(void);
void auth_processes_deinit(void);

#endif
