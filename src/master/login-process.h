#ifndef __LOGIN_PROCESS_H
#define __LOGIN_PROCESS_H

void login_process_abormal_exit(pid_t pid);
void login_processes_destroy_all(void);

void login_processes_init(void);
void login_processes_deinit(void);

#endif
