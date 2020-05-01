#ifndef LMTP_RECIPIENT_H
#define LMTP_RECIPIENT_H

struct smtp_address;
struct smtp_server_cmd_ctx;
struct smtp_server_cmd_rcpt;
struct smtp_server_recipient;
union lmtp_recipient_module_context;
struct client;

enum lmtp_recipient_type {
	LMTP_RECIPIENT_TYPE_LOCAL,
	LMTP_RECIPIENT_TYPE_PROXY,
};

struct lmtp_recipient {
	struct client *client;
	struct smtp_server_recipient *rcpt;

	enum lmtp_recipient_type type;
	void *backend_context;

	const char *forward_fields;

	/* Module-specific contexts. */
	ARRAY(union lmtp_recipient_module_context *) module_contexts;
};

struct lmtp_recipient_module_register {
	unsigned int id;
};

union lmtp_recipient_module_context {
	struct lmtp_recipient_module_register *reg;
};
extern struct lmtp_recipient_module_register lmtp_recipient_module_register;

struct lmtp_recipient *
lmtp_recipient_create(struct client *client,
		      struct smtp_server_recipient *rcpt);

struct lmtp_recipient *
lmtp_recipient_find_duplicate(struct lmtp_recipient *lrcpt,
			      struct smtp_server_transaction *trans);

#endif
