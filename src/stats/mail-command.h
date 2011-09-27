#ifndef MAIL_COMMAND_H
#define MAIL_COMMAND_H

struct mail_command;

extern struct mail_command *stable_mail_commands_head;
extern struct mail_command *stable_mail_commands_tail;

int mail_command_update_parse(const char *const *args, const char **error_r);

void mail_command_ref(struct mail_command *cmd);
void mail_command_unref(struct mail_command **cmd);

void mail_commands_free_memory(void);
void mail_commands_init(void);
void mail_commands_deinit(void);

#endif
