#ifndef POP3_COMMANDS_H
#define POP3_COMMANDS_H

struct pop3_command_context;

struct pop3_command {
	const char *name;
	int (*func)(struct pop3_command_context *cctx);
};

struct pop3_command_context {
	struct client *client;
	const struct pop3_command *command;
	const char *orig_command;
	const char *orig_args;
	const char *args;
	struct event *event;

	struct {
		uint64_t bytes_in;
		uint64_t bytes_out;
	} stats;
};

const struct pop3_command *pop3_command_find(const char *name);
int client_command_execute(struct pop3_command_context *cctx);

#endif
