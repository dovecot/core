#ifndef MAIL_SEARCH_BUILD_H
#define MAIL_SEARCH_BUILD_H

#include "mail-search.h"
#include "mail-search-register.h"

struct imap_arg;
struct mailbox;

struct mail_search_build_context {
	pool_t pool;
	struct mail_search_register *reg;

	struct mail_search_arg *parent;
	const char *error;
};

/* Start building a new search query. Use mail_search_args_unref() to
   free it. */
struct mail_search_args *mail_search_build_init(void);

/* Convert IMAP SEARCH command compatible parameters to mail_search_args. */
int mail_search_build_from_imap_args(struct mail_search_register *reg,
				     const struct imap_arg *imap_args,
				     const char *charset,
				     struct mail_search_args **args_r,
				     const char **error_r);

/* Add SEARCH_ALL to search args. */
void mail_search_build_add_all(struct mail_search_args *args);
/* Add a sequence set to search args. */
void mail_search_build_add_seqset(struct mail_search_args *args,
				  uint32_t seq1, uint32_t seq2);

int mail_search_build_next_astring(struct mail_search_build_context *ctx,
				   const struct imap_arg **imap_args,
				   const char **value_r);

struct mail_search_arg *
mail_search_build_new(struct mail_search_build_context *ctx,
		      enum mail_search_arg_type type);
struct mail_search_arg *
mail_search_build_str(struct mail_search_build_context *ctx,
		      const struct imap_arg **imap_args,
		      enum mail_search_arg_type type);
struct mail_search_arg *
mail_search_build_next(struct mail_search_build_context *ctx,
		       struct mail_search_arg *parent,
		       const struct imap_arg **imap_args);
struct mail_search_arg *
mail_search_build_list(struct mail_search_build_context *ctx,
		       const struct imap_arg *imap_args);

#endif
