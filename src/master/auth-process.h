#ifndef __AUTH_PROCESS_H
#define __AUTH_PROCESS_H

/* cookie_reply is NULL if some error occured */
typedef void (*AuthCallback)(AuthCookieReplyData *cookie_reply,
			     void *context);

typedef struct _AuthProcess AuthProcess;

/* Find process for given id */
AuthProcess *auth_process_find(int id);

/* Request information about given cookie */
void auth_process_request(AuthProcess *process, int id,
			  unsigned char cookie[AUTH_COOKIE_SIZE],
			  AuthCallback callback, void *context);

/* Close any fds used by auth processes */
void auth_processes_destroy_all(void);

void auth_processes_init(void);
void auth_processes_deinit(void);

#endif
