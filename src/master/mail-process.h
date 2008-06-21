#ifndef MAIL_PROCESS_H
#define MAIL_PROCESS_H

#include "master-login-interface.h"
#include "child-process.h"

struct mail_login_request {
	int fd;
	enum master_login_flags flags;
	unsigned int cmd_tag_size;
	unsigned int data_size;
	struct ip_addr local_ip, remote_ip;
};

struct login_group;
struct auth_master_reply;

void mail_process_exec(const char *protocol, const char **args) ATTR_NORETURN;

enum master_login_status
create_mail_process(enum process_type process_type, struct settings *set,
		    const struct mail_login_request *request,
		    const char *user, const char *const *args,
		    const unsigned char *data, bool dump_capability);

void mail_processes_init(void);
void mail_processes_deinit(void);

#endif
