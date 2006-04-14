#ifndef __MAIL_PROCESS_H
#define __MAIL_PROCESS_H

struct login_group;
struct auth_master_reply;

void mail_process_exec(const char *protocol, const char *section);

bool create_mail_process(enum process_type process_type, struct settings *set,
			 int socket, const struct ip_addr *local_ip,
			 const struct ip_addr *remote_ip,
			 const char *user, const char *const *args,
			 bool dump_capability);

void mail_process_destroyed(pid_t pid);

#endif
