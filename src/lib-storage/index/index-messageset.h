#ifndef __INDEX_MESSAGESET_H
#define __INDEX_MESSAGESET_H

struct index_mailbox;

struct messageset_mail {
	struct mail_index_record *rec;
	unsigned int client_seq;
	unsigned int idx_seq;
};

struct messageset_context;

struct messageset_context *
index_messageset_init(struct index_mailbox *ibox,
		      const char *messageset, int uidset);

struct messageset_context *
index_messageset_init_range(struct index_mailbox *ibox,
			    unsigned int num1, unsigned int num2, int uidset);

/* Returns 1 if all were found, 0 if some messages were deleted,
   -1 if internal error occured or -2 if messageset was invalid. */
int index_messageset_deinit(struct messageset_context *ctx);

const struct messageset_mail *
index_messageset_next(struct messageset_context *ctx);

#endif
