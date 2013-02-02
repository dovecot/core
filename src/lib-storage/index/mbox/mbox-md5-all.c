/* Copyright (c) 2004-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "md5.h"
#include "message-parser.h"
#include "mbox-md5.h"

#include <stdlib.h>

struct mbox_md5_context {
	struct md5_context hdr_md5_ctx;
};

static struct mbox_md5_context *mbox_md5_all_init(void)
{
	struct mbox_md5_context *ctx;

	ctx = i_new(struct mbox_md5_context, 1);
	md5_init(&ctx->hdr_md5_ctx);
	return ctx;
}

static void mbox_md5_all_more(struct mbox_md5_context *ctx,
			      struct message_header_line *hdr)
{
	md5_update(&ctx->hdr_md5_ctx, hdr->value, hdr->value_len);
}

static void mbox_md5_all_finish(struct mbox_md5_context *ctx,
				unsigned char result[16])
{
	md5_final(&ctx->hdr_md5_ctx, result);
	i_free(ctx);
}

struct mbox_md5_vfuncs mbox_md5_all = {
	mbox_md5_all_init,
	mbox_md5_all_more,
	mbox_md5_all_finish
};
