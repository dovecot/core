#ifndef IMAPC_CLIENT_H
#define IMAPC_CLIENT_H

enum imapc_command_state {
	IMAPC_COMMAND_STATE_OK,
	IMAPC_COMMAND_STATE_NO,
	IMAPC_COMMAND_STATE_BAD,
	IMAPC_COMMAND_STATE_DISCONNECTED
};

enum imapc_capability {
	IMAPC_CAPABILITY_SASL_IR	= 0x01,
	IMAPC_CAPABILITY_LITERALPLUS	= 0x02,
	IMAPC_CAPABILITY_QRESYNC	= 0x04,

	IMAPC_CAPABILITY_IMAP4REV1	= 0x400000000
};
struct imapc_capability_name {
	const char *name;
	enum imapc_capability capability;
};
extern const struct imapc_capability_name imapc_capability_names[];

struct imapc_client_settings {
	const char *host;
	unsigned int port;

	const char *master_user;
	const char *username;
	const char *password;

	const char *dns_client_socket_path;
};

struct imapc_command_reply {
	enum imapc_command_state state;
	/* "RESP TEXT" when the reply contains [RESP TEXT], otherwise NULL */
	const char *resp_text;
	/* The full tagged reply, including [RESP TEXT]. */
	const char *text;
};

struct imapc_untagged_reply {
	/* name of the untagged reply, e.g. EXISTS */
	const char *name;
	/* number at the beginning of the reply, or 0 if there wasn't any.
	   Set for EXISTS, EXPUNGE, etc. */
	uint32_t num;
	/* the rest of the reply can be read from these args. */
	const struct imap_arg *args;

	/* "RESP TEXT" when the reply is "* OK [RESP TEXT]", otherwise NULL */
	const char *resp_text;

	/* If this reply occurred while a mailbox was selected, this contains
	   the mailbox's untagged_context. */
	void *untagged_box_context;
};

/* Called when tagged reply is received for command. */
typedef void imapc_command_callback_t(const struct imapc_command_reply *reply,
				      void *context);
/* Called each time untagged input is received. */
typedef void imapc_untagged_callback_t(const struct imapc_untagged_reply *reply,
				       void *context);

struct imapc_client *
imapc_client_init(const struct imapc_client_settings *set);
void imapc_client_deinit(struct imapc_client **client);

void imapc_client_cmdf(struct imapc_client *client,
		       imapc_command_callback_t *callback, void *context,
		       const char *cmd_fmt, ...) ATTR_FORMAT(4, 5);

void imapc_client_register_untagged(struct imapc_client *client,
				    imapc_untagged_callback_t *callback,
				    void *context);

void imapc_client_run(struct imapc_client *client);
void imapc_client_stop(struct imapc_client *client);

struct imapc_client_mailbox *
imapc_client_mailbox_open(struct imapc_client *client, const char *name,
			  imapc_command_callback_t *callback, void *context,
			  void *untagged_box_context);
void imapc_client_mailbox_close(struct imapc_client_mailbox **box);
void imapc_client_mailbox_cmdf(struct imapc_client_mailbox *box,
			       imapc_command_callback_t *callback,
			       void *context, const char *cmd_fmt, ...)
	ATTR_FORMAT(4, 5);
struct imapc_seqmap *
imapc_client_mailbox_get_seqmap(struct imapc_client_mailbox *box);

#endif
