#ifndef MAIL_SEARCH_BUILD_H
#define MAIL_SEARCH_BUILD_H

struct imap_arg;
struct mailbox;

struct mail_search_arg *
mail_search_build_from_imap_args(pool_t pool, const struct imap_arg *args,
				 const char **error_r);

/* Allocate keywords for search arguments. If change_uidsets is TRUE,
   change uidsets to seqsets. */
void mail_search_args_init(struct mail_search_arg *args,
			   struct mailbox *box, bool change_uidsets);
/* Free keywords. The args can initialized afterwards again if needed. */
void mail_search_args_deinit(struct mail_search_arg *args,
			     struct mailbox *box);

#endif
