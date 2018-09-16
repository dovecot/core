#ifndef IMAP_LIST_H
#define IMAP_LIST_H

#include "mailbox-list-iter.h"

struct imap_list_return_flag_params {
	const char *name;
	const char *mutf7_name;

	enum mailbox_info_flags mbox_flags;
	enum mailbox_list_iter_flags list_flags;
	struct mail_namespace *ns;
};

struct imap_list_return_flag {
	const char *identifier;

	int (*parse)(struct client_command_context *cmd,
		     const struct imap_arg *args, void **context_r);
	void (*send)(struct client_command_context *cmd, void *context,
		     const struct imap_list_return_flag_params *params);
};

void imap_list_return_flag_register(const struct imap_list_return_flag *rflag);
void imap_list_return_flag_unregister(const struct imap_list_return_flag *rflag);

int imap_list_return_flag_parse(struct client_command_context *cmd,
				const char *flag, const struct imap_arg **args,
				const struct imap_list_return_flag **rflag_r,
				void **context_r);
void imap_list_return_flag_send(
	struct client_command_context *cmd,
	const struct imap_list_return_flag *rflag, void *context,
	const struct imap_list_return_flag_params *params);

/* Returns TRUE if anything was added to the string. */
bool imap_mailbox_flags2str(string_t *str, enum mailbox_info_flags flags);

void imap_list_init(void);
void imap_list_deinit(void);

#endif
