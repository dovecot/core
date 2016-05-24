#ifndef MAIL_SEARCH_MIME_BUILD_H
#define	MAIL_SEARCH_MIME_BUILD_H

#include "mail-search.h"
#include "mail-search-build.h"
#include "mail-search-register.h"
#include "mail-search-mime.h"

struct mailbox;

struct mail_search_mime_build_context {
	struct mail_search_build_context *ctx;
	struct mail_search_mime_part *mime_part;

	struct mail_search_mime_arg *parent;
};

/* Start building a new MIMPART search key. Use mail_search_mime_args_unref()
   to free it. */
struct mail_search_mime_part *mail_search_mime_build_init(void);

/* Convert IMAP SEARCH command compatible parameters to
   mail_search_mime_args. */
int mail_search_mime_build(struct mail_search_build_context *bctx,
		      struct mail_search_mime_part **mpart_r);

/* Add new search arg with given type. */
struct mail_search_mime_arg *
mail_search_mime_build_add(pool_t pool,
		      struct mail_search_mime_part *mpart,
		      enum mail_search_mime_arg_type type);

struct mail_search_mime_arg *
mail_search_mime_build_new(struct mail_search_mime_build_context *ctx,
		      enum mail_search_mime_arg_type type);
struct mail_search_mime_arg *
mail_search_mime_build_str(struct mail_search_mime_build_context *ctx,
		      enum mail_search_mime_arg_type type);
/* Returns 0 if arg is returned, -1 if error. */
int mail_search_mime_build_key(struct mail_search_mime_build_context *ctx,
			  struct mail_search_mime_arg *parent,
			  struct mail_search_mime_arg **arg_r);

#endif
