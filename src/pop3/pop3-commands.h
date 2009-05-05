#ifndef POP3_COMMANDS_H
#define POP3_COMMANDS_H

int client_command_execute(struct client *client,
			   const char *name, const char *args);

#endif
