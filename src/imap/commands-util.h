#ifndef __COMMANDS_UTIL_H
#define __COMMANDS_UTIL_H

struct mail_full_flags;

/* If should_exist is TRUE, this function returns TRUE if the mailbox
   exists. If it doesn't exist but would be a valid mailbox name, the
   error message is prefixed with [TRYCREATE].

   If should_exist is FALSE, the should_not_exist specifies if we should
   return TRUE or FALSE if mailbox doesn't exist. */
int client_verify_mailbox_name(struct client *client, const char *mailbox,
			       int should_exist, int should_not_exist);

/* Returns TRUE if mailbox is selected. If not, sends "No mailbox selected"
   error message to client. */
int client_verify_open_mailbox(struct client *client);

/* Synchronize selected mailbox with client by sending EXPUNGE,
   FETCH FLAGS, EXISTS and RECENT responses. */
void client_sync_full(struct client *client);

/* Synchronize all but expunges with client. */
void client_sync_without_expunges(struct client *client);

/* Send last mail storage error message to client. */
void client_send_storage_error(struct client *client);

/* Send untagged error message to client. */
void client_send_untagged_storage_error(struct client *client);

/* Parse flags. Returns TRUE if successful, if not sends an error message to
   client. */
int client_parse_mail_flags(struct client *client, struct imap_arg *args,
                            const struct mailbox_custom_flags *old_flags,
			    struct mail_full_flags *flags);

/* Send FLAGS + PERMANENTFLAGS to client. */
void client_send_mailbox_flags(struct client *client, struct mailbox *box,
			       const char *custom_flags[],
			       unsigned int custom_flags_count);

/* Copy custom flags into dest. dest must have been initialized. */
void client_save_custom_flags(struct mailbox_custom_flags *dest,
			      const char *custom_flags[],
			      unsigned int custom_flags_count);

#endif
