#ifndef __AUTH_PROCESS_H
#define __AUTH_PROCESS_H

/* cookie_reply is NULL if some error occured */
typedef void (*auth_callback_t)(struct auth_cookie_reply_data *cookie_reply,
				void *context);

/* Find process for given id */
struct auth_process *auth_process_find(unsigned int id);

/* Request information about given cookie */
void auth_process_request(unsigned int login_pid,
			  struct auth_process *process, unsigned int id,
			  unsigned char cookie[AUTH_COOKIE_SIZE],
			  auth_callback_t callback, void *context);

/* Close any fds used by auth processes */
void auth_processes_destroy_all(void);

void auth_processes_init(void);
void auth_processes_deinit(void);

#endif
