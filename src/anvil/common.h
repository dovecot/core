#ifndef COMMON_H
#define COMMON_H

#include "lib.h"

/* Error is set and reply=NULL on internal errors. */
typedef void
admin_cmd_callback_t(const char *reply, const char *error, void *context);

extern struct connect_limit *connect_limit;
extern struct penalty *penalty;
extern bool anvil_restarted;

void anvil_refresh_proctitle_delayed(void);

void admin_cmd_send(const char *service, pid_t pid, const char *cmd,
		    admin_cmd_callback_t *callback, void *context);
#define admin_cmd_send(service, pid, cmd, callback, context) \
	admin_cmd_send(service, pid, cmd, \
		(admin_cmd_callback_t *)callback, \
		TRUE ? context : CALLBACK_TYPECHECK(callback, \
				void (*)(const char *, const char *, \
					 typeof(context))))


#endif
