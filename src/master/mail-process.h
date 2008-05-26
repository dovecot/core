#ifndef MAIL_PROCESS_H
#define MAIL_PROCESS_H

#include "child-process.h"

struct login_group;
struct auth_master_reply;

void mail_process_exec(const char *protocol, const char **args) ATTR_NORETURN;

enum master_login_status
create_mail_process(enum process_type process_type, struct settings *set,
		    int socket_fd, const struct ip_addr *local_ip,
		    const struct ip_addr *remote_ip,
		    const char *user, const char *const *args,
		    bool dump_capability);

void mail_processes_init(void);
void mail_processes_deinit(void);

#endif
