#ifndef __MAIL_PROCESS_H
#define __MAIL_PROCESS_H

struct auth_master_reply;

int create_mail_process(int socket, struct ip_addr *ip,
			const char *executable, unsigned int process_size,
			struct auth_master_reply *reply, const char *data);

void mail_process_destroyed(pid_t pid);

#endif
