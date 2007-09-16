#ifndef COMMANDS_H
#define COMMANDS_H

int client_command_execute(struct client *client,
			   const char *name, const char *args);

#endif
