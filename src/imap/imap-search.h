#ifndef IMAP_SEARCH_H
#define IMAP_SEARCH_H

struct imap_arg;
struct mailbox;
struct client_command_context;

/* Builds search arguments based on IMAP arguments. Returns -1 if search
   arguments are invalid, 0 if we have to wait for unambiguity,
   1 if we can continue. */
int imap_search_args_build(struct client_command_context *cmd,
			   const struct imap_arg *args,
			   struct mail_search_arg **search_args_r);

/* Returns -1 if set is invalid, 0 if we have to wait for unambiguity,
   1 if we can continue. */
int imap_search_get_seqset(struct client_command_context *cmd,
			   const char *set, bool uid,
			   struct mail_search_arg **search_arg_r);
int imap_search_get_anyset(struct client_command_context *cmd,
			   const char *set, bool uid,
			   struct mail_search_arg **search_arg_r);

#endif
