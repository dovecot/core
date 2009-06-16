#ifndef IMAP_SYNC_H
#define IMAP_SYNC_H

enum imap_sync_flags {
	IMAP_SYNC_FLAG_SEND_UID	= 0x01,
	IMAP_SYNC_FLAG_SAFE	= 0x02
};

typedef bool imap_sync_callback_t(struct client_command_context *cmd);

struct client;

struct imap_sync_context *
imap_sync_init(struct client *client, struct mailbox *box,
	       enum imap_sync_flags imap_flags, enum mailbox_sync_flags flags);
int imap_sync_deinit(struct imap_sync_context *ctx,
		     struct client_command_context *sync_cmd);
int imap_sync_more(struct imap_sync_context *ctx);

/* Returns TRUE if syncing would be allowed currently. */
bool imap_sync_is_allowed(struct client *client);

bool cmd_sync(struct client_command_context *cmd, enum mailbox_sync_flags flags,
	      enum imap_sync_flags imap_flags, const char *tagline);
bool cmd_sync_callback(struct client_command_context *cmd,
		       enum mailbox_sync_flags flags,
		       enum imap_sync_flags imap_flags,
		       imap_sync_callback_t *callback);
bool cmd_sync_delayed(struct client *client);

#endif
