#ifndef __CHILD_LOGIN_H
#define __CHILD_LOGIN_H

void login_process_abormal_exit(pid_t pid);
void login_processes_cleanup(void);
void login_processes_destroy_all(void);

void login_processes_init(void);
void login_processes_deinit(void);

#endif
