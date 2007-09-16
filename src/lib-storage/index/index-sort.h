#ifndef INDEX_SORT_H
#define INDEX_SORT_H

struct mail_search_sort_program;

struct mail_search_sort_program *
index_sort_program_init(struct mailbox_transaction_context *t,
			const enum mail_sort_type *sort_program);
void index_sort_program_deinit(struct mail_search_sort_program **program);

void index_sort_list_add(struct mail_search_sort_program *program,
			 struct mail *mail);
void index_sort_list_finish(struct mail_search_sort_program *program);

bool index_sort_list_next(struct mail_search_sort_program *program,
			  struct mail *mail);

#endif
