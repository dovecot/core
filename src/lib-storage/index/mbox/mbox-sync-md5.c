/* Copyright (C) 2004 Timo Sirainen */

#include "lib.h"
#include "message-parser.h"
#include "mbox-sync-private.h"

#include <stdlib.h>

static int parse_date(struct mbox_sync_mail_context *ctx,
		      struct message_header_line *hdr)
{
	if (!ctx->seen_received_hdr) {
		/* Received-header contains date too, and more trusted one */
		md5_update(&ctx->hdr_md5_ctx, hdr->value, hdr->value_len);
	}
	return TRUE;
}

static int parse_delivered_to(struct mbox_sync_mail_context *ctx,
			      struct message_header_line *hdr)
{
	md5_update(&ctx->hdr_md5_ctx, hdr->value, hdr->value_len);
	return TRUE;
}

static int parse_message_id(struct mbox_sync_mail_context *ctx,
			    struct message_header_line *hdr)
{
	if (!ctx->seen_received_hdr) {
		/* Received-header contains unique ID too,
		   and more trusted one */
		md5_update(&ctx->hdr_md5_ctx, hdr->value, hdr->value_len);
	}
	return TRUE;
}

static int parse_received(struct mbox_sync_mail_context *ctx,
			  struct message_header_line *hdr)
{
	if (!ctx->seen_received_hdr) {
		/* get only the first received-header */
		md5_update(&ctx->hdr_md5_ctx, hdr->value, hdr->value_len);
		if (!hdr->continues)
			ctx->seen_received_hdr = TRUE;
	}
	return TRUE;
}

static int parse_x_delivery_id(struct mbox_sync_mail_context *ctx,
			       struct message_header_line *hdr)
{
	/* Let the local delivery agent help generate unique ID's but don't
	   blindly trust this header alone as it could just as easily come from
	   the remote. */
	md5_update(&ctx->hdr_md5_ctx, hdr->value, hdr->value_len);
	return TRUE;
}


static struct mbox_sync_header_func md5_header_funcs[] = {
	{ "Date", parse_date },
	{ "Delivered-To", parse_delivered_to },
	{ "Message-ID", parse_message_id },
	{ "Received", parse_received },
	{ "X-Delivery-ID", parse_x_delivery_id }
};
#define MD5_HEADER_FUNCS_COUNT \
	(sizeof(md5_header_funcs) / sizeof(*md5_header_funcs))

void mbox_sync_md5(struct mbox_sync_mail_context *ctx,
		   struct message_header_line *hdr)
{
	struct mbox_sync_header_func *func;

	func = bsearch(hdr->name, md5_header_funcs,
		       MD5_HEADER_FUNCS_COUNT, sizeof(*md5_header_funcs),
		       mbox_sync_bsearch_header_func_cmp);
	if (func != NULL)
		(void)func->func(ctx, hdr);
}
