/* Copyright (c) 2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "charset-utf8.h"
#include "mail-storage-private.h"
#include "mail-search-parser.h"
#include "mail-search-mime-register.h"
#include "mail-search-mime-build.h"

static int mail_search_mime_build_list(struct mail_search_mime_build_context *ctx,
				  struct mail_search_mime_arg **arg_r);

struct mail_search_mime_arg *
mail_search_mime_build_new(struct mail_search_mime_build_context *ctx,
		      enum mail_search_mime_arg_type type)
{
	struct mail_search_mime_arg *arg;

	arg = p_new(ctx->ctx->pool, struct mail_search_mime_arg, 1);
	arg->type = type;
	return arg;
}

struct mail_search_mime_arg *
mail_search_mime_build_str(struct mail_search_mime_build_context *ctx,
		      enum mail_search_mime_arg_type type)
{
	struct mail_search_mime_arg *sarg;
	const char *value;

	sarg = mail_search_mime_build_new(ctx, type);
	if (mail_search_parse_string(ctx->ctx->parser, &value) < 0)
		return NULL;
	sarg->value.str = p_strdup(ctx->ctx->pool, value);
	return sarg;
}

static int
mail_search_mime_build_key_int(struct mail_search_mime_build_context *ctx,
			  struct mail_search_mime_arg *parent,
			  struct mail_search_mime_arg **arg_r)
{
	struct mail_search_mime_arg *sarg;
	struct mail_search_mime_arg *old_parent = ctx->parent;
	const char *key;
	const struct mail_search_mime_register_arg *reg_arg;
	int ret;

	ctx->parent = parent;

	if ((ret = mail_search_parse_key(ctx->ctx->parser, &key)) <= 0)
		return ret;

	if (strcmp(key, MAIL_SEARCH_PARSER_KEY_LIST) == 0) {
		if (mail_search_mime_build_list(ctx, &sarg) < 0)
			return -1;
		if (sarg->value.subargs == NULL) {
			ctx->ctx->_error = "No MIMEPART keys inside list";
			return -1;
		}

		ctx->parent = old_parent;
		*arg_r = sarg;
		return 1;
	}
	key = t_str_ucase(key);

	reg_arg = mail_search_mime_register_find(key);
	if (reg_arg != NULL)
		sarg = reg_arg->build(ctx);
	else {
		sarg = NULL;
		ctx->ctx->_error = p_strconcat
			(ctx->ctx->pool, "Unknown MIMEPART key ", key, NULL);
	}

	ctx->parent = old_parent;
	*arg_r = sarg;
	return sarg == NULL ? -1 : 1;
}

int mail_search_mime_build_key(struct mail_search_mime_build_context *ctx,
			  struct mail_search_mime_arg *parent,
			  struct mail_search_mime_arg **arg_r)
{
	int ret;

	ret = mail_search_mime_build_key_int(ctx, parent, arg_r);
	if (ret <= 0) {
		if (ret == 0)
			ctx->ctx->_error = "Missing MIMEPART key";
		return -1;
	}
	return 0;
}

static int mail_search_mime_build_list(struct mail_search_mime_build_context *ctx,
				  struct mail_search_mime_arg **arg_r)
{
	struct mail_search_mime_arg *sarg, **subargs;
	enum mail_search_mime_arg_type cur_type = SEARCH_MIME_SUB;
	int ret;

	sarg = p_new(ctx->ctx->pool, struct mail_search_mime_arg, 1);
	sarg->type = cur_type;

	subargs = &sarg->value.subargs;
	while ((ret = mail_search_mime_build_key_int(ctx, sarg, subargs)) > 0) {
		if (cur_type == sarg->type) {
			/* expected type */
		} else if (cur_type == SEARCH_MIME_SUB) {
			/* type changed. everything in this list must now
			   belong to this type. */
			cur_type = sarg->type;
		} else {
			ctx->ctx->_error =
				"Use parenthesis when mixing ANDs and ORs";
			return -1;
		}
		subargs = &(*subargs)->next;
		sarg->type = SEARCH_SUB;
	}
	if (ret < 0)
		return -1;
	sarg->type = cur_type;
	*arg_r = sarg;
	return 0;
}

int mail_search_mime_build(struct mail_search_build_context *bctx,
		      struct mail_search_mime_part **mpart_r)
{
  struct mail_search_mime_build_context ctx;
	struct mail_search_mime_part *mpart;
	struct mail_search_mime_arg *root;
	int ret;

	*mpart_r = NULL;

	memset(&ctx, 0, sizeof(ctx));
	ctx.ctx = bctx;
	ctx.mime_part = mpart =
		p_new(bctx->pool, struct mail_search_mime_part, 1);

	if ((ret=mail_search_mime_build_key(&ctx, NULL, &root)) < 0)
		return ret;

	if (root->type == SEARCH_MIME_SUB && !root->match_not) {
		/* simple SUB root */
		mpart->args = root->value.subargs;
	} else {
		mpart->args = root;
	}

	*mpart_r = mpart;
	return 0;
}

struct mail_search_mime_arg *
mail_search_mime_build_add(pool_t pool,
		      struct mail_search_mime_part *mpart,
		      enum mail_search_mime_arg_type type)
{
	struct mail_search_mime_arg *arg;

	arg = p_new(pool, struct mail_search_mime_arg, 1);
	arg->type = type;

	arg->next = mpart->args;
	mpart->args = arg;
	return arg;
}
