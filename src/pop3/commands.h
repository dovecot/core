#ifndef __COMMANDS_H
#define __COMMANDS_H

int client_command_execute(struct client *client,
			   const char *name, const char *args);

#endif
