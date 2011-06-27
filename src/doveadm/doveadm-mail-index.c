/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "strescape.h"
#include "network.h"
#include "write-full.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-search-build.h"
#include "doveadm-settings.h"
#include "doveadm-mail.h"

#define INDEXER_SOCKET_NAME "indexer"
#define INDEXER_HANDSHAKE "VERSION\tindexer\t1\t0\n"

struct index_cmd_context {
	struct doveadm_mail_cmd_context ctx;

	int queue_fd;
	unsigned int queue:1;
	unsigned int have_wildcards:1;
};

static int
cmd_index_box(const struct mailbox_info *info)
{
	struct mailbox *box;
	int ret = 0;

	box = mailbox_alloc(info->ns->list, info->name,
			    MAILBOX_FLAG_KEEP_RECENT |
			    MAILBOX_FLAG_IGNORE_ACLS);

	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ |
			 MAILBOX_SYNC_FLAG_PRECACHE) < 0) {
		i_error("Syncing mailbox %s failed: %s", info->name,
			mail_storage_get_last_error(mailbox_get_storage(box), NULL));
		ret = -1;
	}

	mailbox_free(&box);
	return ret;
}

static void cmd_index_queue(struct index_cmd_context *ctx,
			    struct mail_user *user, const char *mailbox)
{
	T_BEGIN {
		string_t *str = t_str_new(256);

		str_append(str, "APPEND\t0\t");
		str_tabescape_write(str, user->username);
		str_append_c(str, '\t');
		str_tabescape_write(str, mailbox);
		str_append_c(str, '\n');
		if (write_full(ctx->queue_fd, str_data(str), str_len(str)) < 0)
			i_fatal("write(indexer) failed: %m");
	} T_END;
}

static void
cmd_index_run(struct doveadm_mail_cmd_context *_ctx, struct mail_user *user)
{
	struct index_cmd_context *ctx = (struct index_cmd_context *)_ctx;
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_RAW_LIST |
		MAILBOX_LIST_ITER_NO_AUTO_BOXES |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS |
		MAILBOX_LIST_ITER_STAR_WITHIN_NS;
	const enum namespace_type ns_mask =
		NAMESPACE_PRIVATE | NAMESPACE_SHARED | NAMESPACE_PUBLIC;
	struct mailbox_list_iterate_context *iter;
	const struct mailbox_info *info;
	unsigned int i;

	if (ctx->queue && !ctx->have_wildcards) {
		/* we can do this quickly without going through the mailboxes */
		for (i = 0; _ctx->args[i] != NULL; i++)
			cmd_index_queue(ctx, user, _ctx->args[i]);
		return;
	}

	iter = mailbox_list_iter_init_namespaces(user->namespaces, _ctx->args,
						 ns_mask, iter_flags);
	while ((info = mailbox_list_iter_next(iter)) != NULL) {
		if ((info->flags & (MAILBOX_NOSELECT |
				    MAILBOX_NONEXISTENT)) == 0) T_BEGIN {
			if (ctx->queue)
				cmd_index_queue(ctx, user, info->name);
			else
				(void)cmd_index_box(info);
		} T_END;
	}
	if (mailbox_list_iter_deinit(&iter) < 0)
		i_error("Listing mailboxes failed");
}

static void cmd_index_init(struct doveadm_mail_cmd_context *_ctx,
			   const char *const args[])
{
	struct index_cmd_context *ctx = (struct index_cmd_context *)_ctx;
	const char *path;
	unsigned int i;

	if (args[0] == NULL)
		doveadm_mail_help_name("index");
	for (i = 0; args[i] != NULL; i++) {
		if (strchr(args[i], '*') != NULL ||
		    strchr(args[i], '%') != NULL) {
			ctx->have_wildcards = TRUE;
			break;
		}
	}

	if (ctx->queue) {
		path = t_strconcat(doveadm_settings->base_dir,
				   "/"INDEXER_SOCKET_NAME, NULL);
		ctx->queue_fd = net_connect_unix(path);
		if (ctx->queue_fd == -1)
			i_fatal("net_connect_unix(%s) failed: %m", path);
		if (write_full(ctx->queue_fd, INDEXER_HANDSHAKE,
			       strlen(INDEXER_HANDSHAKE)) < 0)
			i_fatal("write(indexer) failed: %m");
	}
}

static void cmd_index_deinit(struct doveadm_mail_cmd_context *_ctx)
{
	struct index_cmd_context *ctx = (struct index_cmd_context *)_ctx;

	if (ctx->queue_fd != -1) {
		net_disconnect(ctx->queue_fd);
		ctx->queue_fd = -1;
	}
}

static bool
cmd_index_parse_arg(struct doveadm_mail_cmd_context *_ctx, int c)
{
	struct index_cmd_context *ctx = (struct index_cmd_context *)_ctx;

	switch (c) {
	case 'q':
		ctx->queue = TRUE;
		break;
	default:
		return FALSE;
	}
	return TRUE;
}

static struct doveadm_mail_cmd_context *cmd_index_alloc(void)
{
	struct index_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct index_cmd_context);
	ctx->queue_fd = -1;
	ctx->ctx.getopt_args = "q";
	ctx->ctx.v.parse_arg = cmd_index_parse_arg;
	ctx->ctx.v.init = cmd_index_init;
	ctx->ctx.v.deinit = cmd_index_deinit;
	ctx->ctx.v.run = cmd_index_run;
	return &ctx->ctx;
}

struct doveadm_mail_cmd cmd_index = {
	cmd_index_alloc, "index", "[-q] <mailbox>"
};
