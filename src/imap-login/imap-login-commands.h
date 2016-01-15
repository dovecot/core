#ifndef IMAP_LOGIN_COMMANDS_H
#define IMAP_LOGIN_COMMANDS_H

struct imap_arg;
struct imap_client;

typedef int imap_login_command_t(struct imap_client *client,
				 const struct imap_arg *args);

struct imap_login_command {
	const char *name;
	imap_login_command_t *func;
};

struct imap_login_command *imap_login_command_lookup(const char *name);

void imap_login_commands_register(const struct imap_login_command *commands,
				  unsigned int count);
void imap_login_commands_unregister(const struct imap_login_command *commands,
				    unsigned int count);

void imap_login_commands_init(void);
void imap_login_commands_deinit(void);

#endif
