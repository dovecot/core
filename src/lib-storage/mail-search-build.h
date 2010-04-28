#ifndef MAIL_SEARCH_BUILD_H
#define MAIL_SEARCH_BUILD_H

#include "mail-search.h"
#include "mail-search-register.h"

struct mailbox;

struct mail_search_build_context {
	pool_t pool;
	struct mail_search_register *reg;
	struct mail_search_parser *parser;

	struct mail_search_arg *parent;
	/* error is either here or in parser */
	const char *_error;
};

/* Start building a new search query. Use mail_search_args_unref() to
   free it. */
struct mail_search_args *mail_search_build_init(void);

/* Convert IMAP SEARCH command compatible parameters to mail_search_args. */
int mail_search_build(struct mail_search_register *reg,
		      struct mail_search_parser *parser, const char *charset,
		      struct mail_search_args **args_r, const char **error_r);

/* Add new search arg with given type. */
struct mail_search_arg *
mail_search_build_add(struct mail_search_args *args,
		      enum mail_search_arg_type type);
/* Add SEARCH_ALL to search args. */
void mail_search_build_add_all(struct mail_search_args *args);
/* Add a sequence set to search args. */
void mail_search_build_add_seqset(struct mail_search_args *args,
				  uint32_t seq1, uint32_t seq2);

struct mail_search_arg *
mail_search_build_new(struct mail_search_build_context *ctx,
		      enum mail_search_arg_type type);
struct mail_search_arg *
mail_search_build_str(struct mail_search_build_context *ctx,
		      enum mail_search_arg_type type);
/* Returns 0 if arg is returned, -1 if error. */
int mail_search_build_key(struct mail_search_build_context *ctx,
			  struct mail_search_arg *parent,
			  struct mail_search_arg **arg_r);

#endif
