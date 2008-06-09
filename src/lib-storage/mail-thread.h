#ifndef MAIL_THREAD_H
#define MAIL_THREAD_H

struct mail_thread_context;

enum mail_thread_type {
	MAIL_THREAD_NONE,
	MAIL_THREAD_ORDEREDSUBJECT,
	MAIL_THREAD_REFERENCES,
	MAIL_THREAD_REFERENCES2
};

struct mail_thread_child_node {
	/* Node's index in mail hash transaction */
	uint32_t idx;
	/* UID or sequence */
	uint32_t uid;
	/* Timestamp node was sorted with (depends on thread algorithm) */
	time_t sort_date;
};
ARRAY_DEFINE_TYPE(mail_thread_child_node, struct mail_thread_child_node);

/* Build thread from given search arguments. If reset=TRUE, build a new thread
   tree to memory even if thread index exists. */
int mail_thread_init(struct mailbox *box, bool reset,
		     struct mail_search_args *args,
		     struct mail_thread_context **ctx_r);
void mail_thread_deinit(struct mail_thread_context **ctx);

/* Iterate through thread tree. If write_seqs=TRUE, sequences are returned in
   mail_thread_child_node.uid instead of UIDs. */
struct mail_thread_iterate_context *
mail_thread_iterate_init(struct mail_thread_context *ctx,
			 enum mail_thread_type thread_type, bool write_seqs);
/* If child_iter_r is not NULL, it's set to contain another iterator if the
   returned node contains children. The returned iterator must be freed
   explicitly. */
const struct mail_thread_child_node *
mail_thread_iterate_next(struct mail_thread_iterate_context *iter,
			 struct mail_thread_iterate_context **child_iter_r);
/* Returns number of nodes in the current iterator. */
unsigned int
mail_thread_iterate_count(struct mail_thread_iterate_context *iter);
/* Free the iterator. Iterators don't reference other iterators, so it doesn't
   matter in which order they're freed. */
int mail_thread_iterate_deinit(struct mail_thread_iterate_context **iter);

#endif
