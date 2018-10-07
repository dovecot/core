#ifndef SUBMISSION_RECIPIENT_H
#define SUBMISSION_RECIPIENT_H

struct submission_backend;
struct client;

struct submission_recipient {
	struct smtp_server_recipient *rcpt;

	struct submission_backend *backend;

	struct smtp_address *path;
	unsigned int index;

	/* Module-specific contexts. */
	ARRAY(union submission_recipient_module_context *) module_contexts;
};

struct submission_recipient_module_register {
	unsigned int id;
};

union submission_recipient_module_context {
	struct submission_recipient_module_register *reg;
};
extern struct submission_recipient_module_register
submission_recipient_module_register;

struct submission_recipient *
submission_recipient_create(struct client *client,
			    struct smtp_server_recipient *rcpt);

#endif
