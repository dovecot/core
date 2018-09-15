#ifndef SUBMISSION_RECIPIENT_H
#define SUBMISSION_RECIPIENT_H

struct client;

struct submission_recipient {
	struct client *client;

	struct smtp_address *path;
	unsigned int index;
};

struct submission_recipient *
submission_recipient_create(struct client *client, struct smtp_address *path);
void submission_recipient_destroy(struct submission_recipient **_rcpt);
void submission_recipient_finished(struct submission_recipient *rcpt,
				   struct smtp_server_recipient *trcpt,
				   unsigned int index);

#endif
