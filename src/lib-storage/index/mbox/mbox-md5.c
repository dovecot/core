/* Copyright (c) 2004-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "md5.h"
#include "message-parser.h"
#include "mbox-md5.h"

#include <stdlib.h>

struct mbox_md5_context {
	struct md5_context hdr_md5_ctx;
	bool seen_received_hdr;
};

struct mbox_md5_header_func {
	const char *header;
	bool (*func)(struct mbox_md5_context *ctx,
		     struct message_header_line *hdr);
};

static bool parse_date(struct mbox_md5_context *ctx,
		       struct message_header_line *hdr)
{
	if (!ctx->seen_received_hdr) {
		/* Received-header contains date too, and more trusted one */
		md5_update(&ctx->hdr_md5_ctx, hdr->value, hdr->value_len);
	}
	return TRUE;
}

static bool parse_delivered_to(struct mbox_md5_context *ctx,
			       struct message_header_line *hdr)
{
	md5_update(&ctx->hdr_md5_ctx, hdr->value, hdr->value_len);
	return TRUE;
}

static bool parse_message_id(struct mbox_md5_context *ctx,
			     struct message_header_line *hdr)
{
	if (!ctx->seen_received_hdr) {
		/* Received-header contains unique ID too,
		   and more trusted one */
		md5_update(&ctx->hdr_md5_ctx, hdr->value, hdr->value_len);
	}
	return TRUE;
}

static bool parse_received(struct mbox_md5_context *ctx,
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

static bool parse_x_delivery_id(struct mbox_md5_context *ctx,
				struct message_header_line *hdr)
{
	/* Let the local delivery agent help generate unique ID's but don't
	   blindly trust this header alone as it could just as easily come from
	   the remote. */
	md5_update(&ctx->hdr_md5_ctx, hdr->value, hdr->value_len);
	return TRUE;
}


static struct mbox_md5_header_func md5_header_funcs[] = {
	{ "Date", parse_date },
	{ "Delivered-To", parse_delivered_to },
	{ "Message-ID", parse_message_id },
	{ "Received", parse_received },
	{ "X-Delivery-ID", parse_x_delivery_id }
};

static int bsearch_header_func_cmp(const void *p1, const void *p2)
{
	const char *key = p1;
	const struct mbox_md5_header_func *func = p2;

	return strcasecmp(key, func->header);
}

struct mbox_md5_context *mbox_md5_init(void)
{
	struct mbox_md5_context *ctx;

	ctx = i_new(struct mbox_md5_context, 1);
	md5_init(&ctx->hdr_md5_ctx);
	return ctx;
}

void mbox_md5_continue(struct mbox_md5_context *ctx,
		       struct message_header_line *hdr)
{
	struct mbox_md5_header_func *func;

	func = bsearch(hdr->name, md5_header_funcs,
		       N_ELEMENTS(md5_header_funcs), sizeof(*md5_header_funcs),
		       bsearch_header_func_cmp);
	if (func != NULL)
		(void)func->func(ctx, hdr);
}

void mbox_md5_finish(struct mbox_md5_context *ctx,
		     unsigned char result[16])
{
	md5_final(&ctx->hdr_md5_ctx, result);
	i_free(ctx);
}
