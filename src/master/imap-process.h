#ifndef __IMAP_PROCESS_H
#define __IMAP_PROCESS_H

struct auth_master_reply;

int create_imap_process(int socket, struct ip_addr *ip,
			struct auth_master_reply *reply, const char *data);
void imap_process_destroyed(pid_t pid);

#endif
