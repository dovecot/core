#ifndef __MAIL_PROCESS_H
#define __MAIL_PROCESS_H

struct login_group;
struct auth_master_reply;

void mail_process_exec(const char *protocol, const char *section);

int create_mail_process(struct login_group *group, int socket,
			const struct ip_addr *local_ip,
			const struct ip_addr *remote_ip,
			const char *user, const char *const *args);

void mail_process_destroyed(pid_t pid);

#endif
