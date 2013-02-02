/* Copyright (c) 2006-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "imap-match.h"
#include "mailbox-list-private.h"

#define GLOBAL_TEMP_PREFIX ".temp."

struct noop_list_iterate_context {
	struct mailbox_list_iterate_context ctx;
	struct mailbox_info inbox_info;
	unsigned int list_inbox:1;
};

extern struct mailbox_list none_mailbox_list;

static struct mailbox_list *none_list_alloc(void)
{
	struct mailbox_list *list;
	pool_t pool;

	pool = pool_alloconly_create("none list", 2048);

	list = p_new(pool, struct mailbox_list, 1);
	*list = none_mailbox_list;
	list->pool = pool;
	return list;
}

static void none_list_deinit(struct mailbox_list *list)
{
	pool_unref(&list->pool);
}

static char none_list_get_hierarchy_sep(struct mailbox_list *list ATTR_UNUSED)
{
	return '/';
}

static int
none_list_get_path(struct mailbox_list *list ATTR_UNUSED,
		   const char *name ATTR_UNUSED,
		   enum mailbox_list_path_type type ATTR_UNUSED,
		   const char **path_r ATTR_UNUSED)
{
	return 0;
}

static const char *
none_list_get_temp_prefix(struct mailbox_list *list ATTR_UNUSED,
			  bool global ATTR_UNUSED)
{
	return GLOBAL_TEMP_PREFIX;
}

static int
none_list_subscriptions_refresh(struct mailbox_list *src_list ATTR_UNUSED,
				struct mailbox_list *dest_list ATTR_UNUSED)
{
	return 0;
}

static int none_list_set_subscribed(struct mailbox_list *list,
				    const char *name ATTR_UNUSED,
				    bool set ATTR_UNUSED)
{
	mailbox_list_set_error(list, MAIL_ERROR_NOTPOSSIBLE, "Not supported");
	return -1;
}

static int none_list_delete_mailbox(struct mailbox_list *list,
				    const char *name ATTR_UNUSED)
{
	mailbox_list_set_error(list, MAIL_ERROR_NOTPOSSIBLE, "Not supported");
	return -1;
}

static int none_list_delete_dir(struct mailbox_list *list,
				const char *name ATTR_UNUSED)
{
	mailbox_list_set_error(list, MAIL_ERROR_NOTPOSSIBLE, "Not supported");
	return -1;
}

static int
none_list_rename_mailbox(struct mailbox_list *oldlist,
			 const char *oldname ATTR_UNUSED,
			 struct mailbox_list *newlist ATTR_UNUSED,
			 const char *newname ATTR_UNUSED)
{
	mailbox_list_set_error(oldlist, MAIL_ERROR_NOTPOSSIBLE,
			       "Not supported");
	return -1;
}

static struct mailbox_list_iterate_context *
none_list_iter_init(struct mailbox_list *list,
		    const char *const *patterns,
		    enum mailbox_list_iter_flags flags)
{
	struct noop_list_iterate_context *ctx;
	pool_t pool;

	pool = pool_alloconly_create("mailbox list none iter", 1024);
	ctx = p_new(pool, struct noop_list_iterate_context, 1);
	ctx->ctx.pool = pool;
	ctx->ctx.list = list;
	ctx->ctx.flags = flags;
	ctx->ctx.glob = imap_match_init_multiple(pool, patterns, TRUE,
						 mail_namespace_get_sep(list->ns));
	array_create(&ctx->ctx.module_contexts, pool, sizeof(void *), 5);
	if ((list->ns->flags & NAMESPACE_FLAG_INBOX_USER) != 0 &&
	    imap_match(ctx->ctx.glob, "INBOX") == IMAP_MATCH_YES) {
		ctx->list_inbox = TRUE;
		ctx->inbox_info.ns = list->ns;
		ctx->inbox_info.vname = "INBOX";
	}
	return &ctx->ctx;
}

static int
none_list_iter_deinit(struct mailbox_list_iterate_context *ctx)
{
	pool_unref(&ctx->pool);
	return 0;
}

static const struct mailbox_info *
none_list_iter_next(struct mailbox_list_iterate_context *_ctx)
{
	struct noop_list_iterate_context *ctx =
		(struct noop_list_iterate_context *)_ctx;

	if (ctx->list_inbox) {
		ctx->list_inbox = FALSE;
		return &ctx->inbox_info;
	}
	return NULL;
}

static int
none_list_get_mailbox_flags(struct mailbox_list *list ATTR_UNUSED,
			    const char *dir ATTR_UNUSED,
			    const char *fname ATTR_UNUSED,
			    enum mailbox_list_file_type type ATTR_UNUSED,
			    enum mailbox_info_flags *flags)
{
	*flags = MAILBOX_NONEXISTENT;
	return 0;
}

struct mailbox_list none_mailbox_list = {
	.name = MAILBOX_LIST_NAME_NONE,
	.props = MAILBOX_LIST_PROP_NO_ROOT,
	.mailbox_name_max_length = MAILBOX_LIST_NAME_MAX_LENGTH,

	{
		none_list_alloc,
		NULL,
		none_list_deinit,
		NULL,
		none_list_get_hierarchy_sep,
		mailbox_list_default_get_vname,
		mailbox_list_default_get_storage_name,
		none_list_get_path,
		none_list_get_temp_prefix,
		NULL,
		none_list_iter_init,
		none_list_iter_next,
		none_list_iter_deinit,
		none_list_get_mailbox_flags,
		NULL,
		none_list_subscriptions_refresh,
		none_list_set_subscribed,
		none_list_delete_mailbox,
		none_list_delete_dir,
		none_list_delete_dir,
		none_list_rename_mailbox,
		NULL, NULL, NULL, NULL
	}
};
