#ifndef IMAP_NOTIFY_H
#define IMAP_NOTIFY_H

enum imap_notify_type {
	IMAP_NOTIFY_TYPE_SUBSCRIBED,
	IMAP_NOTIFY_TYPE_SUBTREE,
	IMAP_NOTIFY_TYPE_MAILBOX
};

enum imap_notify_event {
	IMAP_NOTIFY_EVENT_MESSAGE_NEW		= 0x01,
	IMAP_NOTIFY_EVENT_MESSAGE_EXPUNGE	= 0x02,
	IMAP_NOTIFY_EVENT_FLAG_CHANGE		= 0x04,
	IMAP_NOTIFY_EVENT_ANNOTATION_CHANGE	= 0x08,
	IMAP_NOTIFY_EVENT_MAILBOX_NAME		= 0x10,
	IMAP_NOTIFY_EVENT_SUBSCRIPTION_CHANGE	= 0x20,
	IMAP_NOTIFY_EVENT_MAILBOX_METADATA_CHANGE = 0x40,
	IMAP_NOTIFY_EVENT_SERVER_METADATA_CHANGE = 0x80
};
#define UNSUPPORTED_EVENTS \
	(IMAP_NOTIFY_EVENT_ANNOTATION_CHANGE | \
	 IMAP_NOTIFY_EVENT_MAILBOX_METADATA_CHANGE | \
	 IMAP_NOTIFY_EVENT_SERVER_METADATA_CHANGE)

struct imap_notify_mailboxes {
	enum imap_notify_event events;
	enum imap_notify_type type;
	ARRAY_TYPE(const_string) names;
};

struct imap_notify_namespace {
	struct imap_notify_context *ctx;
	struct mail_namespace *ns;

	struct mailbox_list_notify *notify;
	ARRAY(struct imap_notify_mailboxes) mailboxes;
};

struct imap_notify_context {
	pool_t pool;
	struct client *client;
	const char *error;

	ARRAY(struct imap_notify_namespace) namespaces;
	enum imap_notify_event selected_events;
	enum imap_notify_event global_used_events;
	unsigned int global_max_mailbox_names;

	struct imap_fetch_context *fetch_ctx;
	struct timeout *to_watch;

	unsigned int selected_set:1;
	unsigned int selected_immediate_expunges:1;
	unsigned int send_immediate_status:1;
	unsigned int watching_mailbox:1;
	unsigned int notifying:1;
};

bool imap_notify_match_mailbox(struct imap_notify_namespace *notify_ns,
			       const struct imap_notify_mailboxes *notify_boxes,
			       const char *vname);

int imap_client_notify_newmails(struct client *client);
void imap_client_notify_finished(struct client *client);

void imap_client_notify_command_freed(struct client *client);

int imap_notify_begin(struct imap_notify_context *ctx);
void imap_notify_deinit(struct imap_notify_context **ctx);

#endif
