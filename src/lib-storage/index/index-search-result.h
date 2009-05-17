#ifndef INDEX_SEARCH_RESULT_H
#define INDEX_SEARCH_RESULT_H

int index_search_result_update_flags(struct mail_search_result *result,
				     const ARRAY_TYPE(seq_range) *uids);
int index_search_result_update_appends(struct mail_search_result *result,
				       unsigned int old_messages_count);
void index_search_results_update_expunges(struct mailbox *box,
					  const ARRAY_TYPE(seq_range) *expunges);

#endif
