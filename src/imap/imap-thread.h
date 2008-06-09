#ifndef IMAP_THREAD_H
#define IMAP_THREAD_H

struct imap_thread_context;

enum mail_thread_type {
	MAIL_THREAD_NONE,
	MAIL_THREAD_ORDEREDSUBJECT,
	MAIL_THREAD_REFERENCES,
	MAIL_THREAD_REFERENCES2
};

struct mail_thread_child_node {
	uint32_t idx;
	uint32_t uid;
	time_t sort_date;
};
ARRAY_DEFINE_TYPE(mail_thread_child_node, struct mail_thread_child_node);

int imap_thread_init(struct mailbox *box, bool reset,
		     struct mail_search_args *args,
		     struct imap_thread_context **ctx_r);
void imap_thread_deinit(struct imap_thread_context **ctx);

struct mail_thread_iterate_context *
imap_thread_iterate_init(struct imap_thread_context *ctx,
			 enum mail_thread_type thread_type, bool write_seqs);
const struct mail_thread_child_node *
mail_thread_iterate_next(struct mail_thread_iterate_context *iter,
			 struct mail_thread_iterate_context **child_iter_r);
unsigned int
mail_thread_iterate_count(struct mail_thread_iterate_context *iter);
int mail_thread_iterate_deinit(struct mail_thread_iterate_context **iter);

void imap_threads_init(void);
void imap_threads_deinit(void);

#endif
