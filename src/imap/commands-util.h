#ifndef __COMMANDS_UTIL_H
#define __COMMANDS_UTIL_H

/* If should_exist is TRUE, this function returns TRUE if the mailbox
   exists. If it doesn't exist but would be a valid mailbox name, the
   error message is prefixed with [TRYCREATE].

   If should_exist is FALSE, this function returns TRUE if the mailbox
   name is valid and doesn't exist. */
int client_verify_mailbox_name(Client *client, const char *mailbox,
			       int should_exist);

/* Returns TRUE if mailbox is selected. If not, sends "No mailbox selected"
   error message to client. */
int client_verify_open_mailbox(Client *client);

/* Synchronize selected mailbox with client by sending EXPUNGE and
   FETCH FLAGS responses. */
void client_sync_mailbox(Client *client);

/* Synchronize selected mailbox and expunge messages with \Deleted flag. */
int client_sync_and_expunge_mailbox(Client *client);

/* Send last mail storage error message to client. */
void client_send_storage_error(Client *client);

/* Parse flags, stores custom flag names into custflags[]. The names point to
   strings in ImapArgList. Returns TRUE if successful, if not sends an error
   message to client. */
int client_parse_mail_flags(Client *client, ImapArgList *list, MailFlags *flags,
			    const char *custflags[MAIL_CUSTOM_FLAGS_COUNT]);

#endif
