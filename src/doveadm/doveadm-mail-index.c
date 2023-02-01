/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "strescape.h"
#include "connection.h"
#include "istream.h"
#include "ostream.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-search-build.h"
#include "mailbox-list-iter.h"
#include "doveadm-settings.h"
#include "doveadm-mail.h"

#include <stdio.h>

#define INDEXER_SOCKET_NAME "indexer"

struct index_cmd_context {
	struct doveadm_mail_cmd_context ctx;

	const char *const *mailboxes;
	struct istream *queue_input;
	struct ostream *queue_output;
	unsigned int max_recent_msgs;
	bool queue:1;
	bool have_wildcards:1;
};

static int cmd_index_box_precache(struct doveadm_mail_cmd_context *dctx,
				  struct mailbox *box)
{
	struct event *event = dctx->cctx->event;
	struct mailbox_status status;
	struct mailbox_transaction_context *trans;
	struct mail_search_args *search_args;
	struct mail_search_context *ctx;
	struct mail *mail;
	struct mailbox_metadata metadata;
	uint32_t seq;
	unsigned int counter = 0, max;
	int ret = 0;

	if (mailbox_get_metadata(box, MAILBOX_METADATA_PRECACHE_FIELDS,
				 &metadata) < 0) {
		e_error(event, "Mailbox %s: Precache-fields lookup failed: %s",
			mailbox_get_vname(box),
			mailbox_get_last_internal_error(box, NULL));
	}
	if (mailbox_get_status(box, STATUS_MESSAGES | STATUS_LAST_CACHED_SEQ,
			       &status) < 0) {
		e_error(event, "Mailbox %s: Status lookup failed: %s",
			mailbox_get_vname(box),
			mailbox_get_last_internal_error(box, NULL));
		return -1;
	}

	seq = status.last_cached_seq + 1;
	if (seq > status.messages) {
		if (doveadm_verbose) {
			e_info(event, "%s: Cache is already up to date",
			       mailbox_get_vname(box));
		}
		return 0;
	}
	if (doveadm_verbose) {
		e_info(event, "%s: Caching mails seq=%u..%u",
		       mailbox_get_vname(box), seq, status.messages);
	}

	trans = mailbox_transaction_begin(box, MAILBOX_TRANSACTION_FLAG_NO_CACHE_DEC |
					  dctx->transaction_flags, __func__);
	search_args = mail_search_build_init();
	mail_search_build_add_seqset(search_args, seq, status.messages);
	ctx = mailbox_search_init(trans, search_args, NULL,
				  metadata.precache_fields, NULL);
	mail_search_args_unref(&search_args);

	max = status.messages - seq + 1;
	while (mailbox_search_next(ctx, &mail)) {
		if (mail_precache(mail) < 0) {
			e_error(event,
				"Mailbox %s: Precache for UID=%u failed: %s",
				mailbox_get_vname(box), mail->uid,
				mail_get_last_internal_error(mail, NULL));
			ret = -1;
			break;
		}
		if (doveadm_verbose && ++counter % 100 == 0) {
			printf("\r%u/%u", counter, max);
			fflush(stdout);
		}
	}
	if (doveadm_verbose)
		printf("\r%u/%u\n", counter, max);
	if (mailbox_search_deinit(&ctx) < 0) {
		e_error(event, "Mailbox %s: Mail search failed: %s",
			mailbox_get_vname(box),
			mailbox_get_last_internal_error(box, NULL));
		ret = -1;
	}
	if (mailbox_transaction_commit(&trans) < 0) {
		e_error(event, "Mailbox %s: Transaction commit failed: %s",
			mailbox_get_vname(box),
			mailbox_get_last_internal_error(box, NULL));
		ret = -1;
	}
	return ret;
}

static int
cmd_index_box(struct index_cmd_context *ctx, const struct mailbox_info *info)
{
	struct event *event = ctx->ctx.cctx->event;
	struct mailbox *box;
	struct mailbox_status status;
	int ret = 0;

	box = mailbox_alloc(info->ns->list, info->vname,
			    MAILBOX_FLAG_IGNORE_ACLS);
	if (ctx->max_recent_msgs != 0) {
		/* index only if there aren't too many recent messages.
		   don't bother syncing the mailbox, that alone can take a
		   while with large maildirs. */
		if (mailbox_open(box) < 0) {
			e_error(event,
				"Opening mailbox %s failed: %s", info->vname,
				mailbox_get_last_internal_error(box, NULL));
			doveadm_mail_failed_mailbox(&ctx->ctx, box);
			mailbox_free(&box);
			return -1;
		}

		mailbox_get_open_status(box, STATUS_RECENT, &status);
		if (status.recent > ctx->max_recent_msgs) {
			mailbox_free(&box);
			return 0;
		}
	}

	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FULL_READ) < 0) {
		e_error(event, "Syncing mailbox %s failed: %s", info->vname,
			mailbox_get_last_internal_error(box, NULL));
		doveadm_mail_failed_mailbox(&ctx->ctx, box);
		ret = -1;
	} else {
		if (cmd_index_box_precache(&ctx->ctx, box) < 0) {
			doveadm_mail_failed_mailbox(&ctx->ctx, box);
			ret = -1;
		}
	}
	mailbox_free(&box);
	return ret;
}

static void index_queue_connect(struct index_cmd_context *ctx)
{
	const char *path;

	path = t_strconcat(doveadm_settings->base_dir,
			   "/"INDEXER_SOCKET_NAME, NULL);
	const struct connection_settings set = {
		.service_name_out = "indexer-client",
		.service_name_in = "indexer-server",
		.major_version = 1,
		.minor_version = 0,
	};
	const char *error;
	if (doveadm_blocking_connect(path, &set, &ctx->queue_input,
				     &ctx->queue_output, &error) < 0)
		i_fatal("%s", error);
}

static void cmd_index_queue(struct index_cmd_context *ctx,
			    struct mail_user *user, const char *mailbox)
{
	if (ctx->queue_input == NULL)
		index_queue_connect(ctx);
	i_assert(ctx->queue_input != NULL);

	T_BEGIN {
		string_t *str = t_str_new(256);

		str_append(str, "APPEND\t0\t");
		str_append_tabescaped(str, user->username);
		str_append_c(str, '\t');
		str_append_tabescaped(str, mailbox);
		str_printfa(str, "\t%u\n", ctx->max_recent_msgs);
		o_stream_nsend(ctx->queue_output, str_data(str), str_len(str));
		if (o_stream_flush(ctx->queue_output) < 0) {
			i_fatal("write(indexer) failed: %s",
				o_stream_get_error(ctx->queue_output));
		}
		const char *line;
		if ((line = i_stream_read_next_line(ctx->queue_input)) == NULL) {
			i_fatal("read(indexer) failed: %s",
				i_stream_get_error(ctx->queue_input));
		}
		if (strcmp(line, "0\tOK") != 0)
			i_fatal("indexer: APPEND returned unexpected reply: %s", line);
	} T_END;
}

static int
cmd_index_run(struct doveadm_mail_cmd_context *_ctx, struct mail_user *user)
{
	struct index_cmd_context *ctx =
		container_of(_ctx, struct index_cmd_context, ctx);
	struct event *event = ctx->ctx.cctx->event;
	const enum mailbox_list_iter_flags iter_flags =
		MAILBOX_LIST_ITER_NO_AUTO_BOXES |
		MAILBOX_LIST_ITER_RETURN_NO_FLAGS |
		MAILBOX_LIST_ITER_STAR_WITHIN_NS;
	const enum mail_namespace_type ns_mask = MAIL_NAMESPACE_TYPE_MASK_ALL;
	struct mailbox_list_iterate_context *iter;
	const struct mailbox_info *info;
	int ret = 0;

	if (ctx->queue && !ctx->have_wildcards) {
		/* we can do this quickly without going through the mailboxes */
		const char *const *box = ctx->mailboxes;
		for (; *box != NULL; box++)
			cmd_index_queue(ctx, user, *box);
		return 0;
	}

	iter = mailbox_list_iter_init_namespaces(
		user->namespaces, ctx->mailboxes, ns_mask, iter_flags);
	while ((info = mailbox_list_iter_next(iter)) != NULL) {
		if ((info->flags & (MAILBOX_NOSELECT |
				    MAILBOX_NONEXISTENT)) == 0) T_BEGIN {
			if (ctx->queue)
				cmd_index_queue(ctx, user, info->vname);
			else {
				if (cmd_index_box(ctx, info) < 0)
					ret = -1;
			}
		} T_END;
	}
	if (mailbox_list_iter_deinit(&iter) < 0) {
		e_error(event, "Listing mailboxes failed: %s",
			mailbox_list_get_last_internal_error(user->namespaces->list, NULL));
		doveadm_mail_failed_error(_ctx, MAIL_ERROR_TEMP);
		ret = -1;
	}
	return ret;
}

static void cmd_index_init(struct doveadm_mail_cmd_context *_ctx)
{
	struct doveadm_cmd_context *cctx = _ctx->cctx;
	struct index_cmd_context *ctx =
		container_of(_ctx, struct index_cmd_context, ctx);

	ctx->queue = doveadm_cmd_param_flag(cctx, "queue");
	(void)doveadm_cmd_param_uint32(cctx, "max-recent", &ctx->max_recent_msgs);

	if (!doveadm_cmd_param_array(cctx, "mailbox-mask", &ctx->mailboxes))
		doveadm_mail_help_name("index");

	const char *const *box = ctx->mailboxes;
	for (; !ctx->have_wildcards && *box != NULL; box++)
		ctx->have_wildcards =
			strchr(*box, '*') != NULL ||
			strchr(*box, '%') != NULL;
}

static void cmd_index_deinit(struct doveadm_mail_cmd_context *_ctx)
{
	struct index_cmd_context *ctx =
		container_of(_ctx, struct index_cmd_context, ctx);

	o_stream_destroy(&ctx->queue_output);
	i_stream_destroy(&ctx->queue_input);
}

static struct doveadm_mail_cmd_context *cmd_index_alloc(void)
{
	struct index_cmd_context *ctx;

	ctx = doveadm_mail_cmd_alloc(struct index_cmd_context);
	ctx->ctx.v.init = cmd_index_init;
	ctx->ctx.v.deinit = cmd_index_deinit;
	ctx->ctx.v.run = cmd_index_run;
	return &ctx->ctx;
}

struct doveadm_cmd_ver2 doveadm_cmd_index_ver2 = {
	.name = "index",
	.usage = DOVEADM_CMD_MAIL_USAGE_PREFIX"[-q] [-n <max recent>] <mailbox mask>",
	.mail_cmd = cmd_index_alloc,
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_MAIL_COMMON
DOVEADM_CMD_PARAM('q',"queue",CMD_PARAM_BOOL,0)
DOVEADM_CMD_PARAM('n',"max-recent",CMD_PARAM_INT64,CMD_PARAM_FLAG_UNSIGNED)
DOVEADM_CMD_PARAM('\0',"mailbox-mask",CMD_PARAM_ARRAY,CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};
