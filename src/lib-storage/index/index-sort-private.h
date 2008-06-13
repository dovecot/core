#ifndef INDEX_SORT_PRIVATE_H
#define INDEX_SORT_PRIVATE_H

#include "index-sort.h"

struct mail_search_sort_program {
	struct mailbox_transaction_context *t;
	enum mail_sort_type sort_program[MAX_SORT_PROGRAM_SIZE];
	struct mail *temp_mail;

	void (*sort_list_add)(struct mail_search_sort_program *program,
			      struct mail *mail);
	void (*sort_list_finish)(struct mail_search_sort_program *program);
	void *context;

	ARRAY_TYPE(uint32_t) seqs;
	unsigned int iter_idx;
};

int index_sort_header_get(struct mail *mail, uint32_t seq,
			  enum mail_sort_type sort_type, string_t *dest);
int index_sort_node_cmp_type(struct mail *mail,
			     const enum mail_sort_type *sort_program,
			     uint32_t seq1, uint32_t seq2);

void index_sort_list_init_string(struct mail_search_sort_program *program);
void index_sort_list_add_string(struct mail_search_sort_program *program,
				struct mail *mail);
void index_sort_list_finish_string(struct mail_search_sort_program *program);

#endif
