#ifndef __MAIL_PROCESS_H
#define __MAIL_PROCESS_H

struct login_group;
struct auth_master_reply;

int create_mail_process(struct login_group *group, int socket,
			struct ip_addr *ip,
			struct auth_master_reply *reply, const char *data);

void mail_process_destroyed(pid_t pid);

#endif
