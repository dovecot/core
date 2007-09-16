#ifndef LOGIN_PROCESS_H
#define LOGIN_PROCESS_H

#include "child-process.h"

struct login_group {
	struct login_group *next;
	int refcount;

	enum process_type mail_process_type;
	struct settings *set;

	unsigned int processes;
	unsigned int listening_processes;
	unsigned int wanted_processes_count;

	/* if login_process_per_connection=yes this contains the list of
	   processes that are in LOGIN_STATE_FULL_PRELOGINS state */
	struct login_process *oldest_prelogin_process;
	struct login_process *newest_prelogin_process;
};

void login_processes_destroy_all(void);

void login_processes_init(void);
void login_processes_deinit(void);

#endif
