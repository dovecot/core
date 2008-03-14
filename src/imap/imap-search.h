#ifndef IMAP_SEARCH_H
#define IMAP_SEARCH_H

struct imap_arg;
struct mailbox;
struct client_command_context;

/* Builds search arguments based on IMAP arguments. */
struct mail_search_arg *
imap_search_args_build(pool_t pool, struct mailbox *box,
		       const struct imap_arg *args, const char **error_r);

struct mail_search_arg *
imap_search_get_arg(struct client_command_context *cmd,
		    const char *set, bool uid);

#endif
