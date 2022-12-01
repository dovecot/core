#ifndef POP3_COMMANDS_H
#define POP3_COMMANDS_H

struct pop3_command {
	const char *name;
	int (*func)(struct client *client, const char *args);
};

const struct pop3_command *pop3_command_find(const char *name);
int client_command_execute(struct client *client,
			   const struct pop3_command *cmd, const char *args);

#endif
