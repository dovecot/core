/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "imap-arg.h"
#include "mail-storage-private.h"
#include "mail-search-register.h"
#include "mail-search-build.h"

#include <stdlib.h>

int mail_search_build_next_astring(struct mail_search_build_context *ctx,
				   const struct imap_arg **imap_args,
				   const char **value_r)
{
	if (IMAP_ARG_IS_EOL(*imap_args)) {
		ctx->error = "Missing parameter for argument";
		return -1;
	}
	if (!imap_arg_get_astring(*imap_args, value_r)) {
		ctx->error = "Invalid parameter for argument";
		return -1;
	}

	*imap_args += 1;
	return 0;
}

struct mail_search_arg *
mail_search_build_new(struct mail_search_build_context *ctx,
		      enum mail_search_arg_type type)
{
	struct mail_search_arg *arg;

	arg = p_new(ctx->pool, struct mail_search_arg, 1);
	arg->type = type;
	return arg;
}

struct mail_search_arg *
mail_search_build_str(struct mail_search_build_context *ctx,
		      const struct imap_arg **imap_args,
		      enum mail_search_arg_type type)
{
	struct mail_search_arg *sarg;
	const char *value;

	sarg = mail_search_build_new(ctx, type);
	if (mail_search_build_next_astring(ctx, imap_args, &value) < 0)
		return NULL;
	sarg->value.str = p_strdup(ctx->pool, value);
	return sarg;
}

struct mail_search_arg *
mail_search_build_next(struct mail_search_build_context *ctx,
		       struct mail_search_arg *parent,
		       const struct imap_arg **imap_args)
{
	struct mail_search_arg *sarg;
	struct mail_search_arg *old_parent = ctx->parent;
	const struct imap_arg *listargs;
	const char *key;
	const struct mail_search_register_arg *reg_arg;
	mail_search_register_fallback_t *fallback;

	ctx->parent = parent;

	if (IMAP_ARG_IS_EOL(*imap_args)) {
		ctx->error = "Missing argument";
		return NULL;
	}

	if ((*imap_args)->type == IMAP_ARG_NIL) {
		/* NIL not allowed */
		ctx->error = "NIL not allowed";
		return NULL;
	}

	if (imap_arg_get_list(*imap_args, &listargs)) {
		if (IMAP_ARG_IS_EOL(listargs)) {
			ctx->error = "Empty list not allowed";
			return NULL;
		}

		sarg = mail_search_build_list(ctx, listargs);
		*imap_args += 1;
		ctx->parent = old_parent;
		return sarg;
	}

	/* string argument - get the name and jump to next */
	key = imap_arg_as_astring(*imap_args);
	*imap_args += 1;
	key = t_str_ucase(key);

	reg_arg = mail_search_register_find(ctx->reg, key);
	if (reg_arg != NULL)
		sarg = reg_arg->build(ctx, imap_args);
	else if (mail_search_register_get_fallback(ctx->reg, &fallback))
		sarg = fallback(ctx, key, imap_args);
	else {
		sarg = NULL;
		ctx->error = p_strconcat(ctx->pool, "Unknown argument ",
					 key, NULL);
	}

	ctx->parent = old_parent;
	return sarg;
}

struct mail_search_arg *
mail_search_build_list(struct mail_search_build_context *ctx,
		       const struct imap_arg *imap_args)
{
	struct mail_search_arg *sarg, **subargs;
	enum mail_search_arg_type cur_type = SEARCH_SUB;

	sarg = p_new(ctx->pool, struct mail_search_arg, 1);
	sarg->type = cur_type;

	subargs = &sarg->value.subargs;
	while (!IMAP_ARG_IS_EOL(imap_args)) {
		sarg->type = SEARCH_SUB;
		*subargs = mail_search_build_next(ctx, sarg, &imap_args);
		if (*subargs == NULL)
			return NULL;

		if (cur_type == sarg->type) {
			/* expected type */
		} else if (cur_type == SEARCH_SUB) {
			/* type changed. everything in this list must now
			   belong to this type. */
			cur_type = sarg->type;
		} else {
			ctx->error = cur_type == SEARCH_OR ?
				"Use parenthesis when using ORs" :
				"Use parenthesis when mixing subtypes";
			return NULL;
		}
		subargs = &(*subargs)->next;
	}
	return sarg;
}

int mail_search_build_from_imap_args(struct mail_search_register *reg,
				     const struct imap_arg *imap_args,
				     const char *charset,
				     struct mail_search_args **args_r,
				     const char **error_r)
{
        struct mail_search_build_context ctx;
	struct mail_search_args *args;
	struct mail_search_arg *root;

	*args_r = NULL;
	*error_r = NULL;

	args = mail_search_build_init();
	args->charset = p_strdup(args->pool, charset);

	memset(&ctx, 0, sizeof(ctx));
	ctx.pool = args->pool;
	ctx.reg = reg;

	root = mail_search_build_list(&ctx, imap_args);
	if (root == NULL) {
		*error_r = t_strdup(ctx.error);
		pool_unref(&args->pool);
		return -1;
	}

	if (root->type == SEARCH_SUB && !root->not) {
		/* simple SUB root */
		args->args = root->value.subargs;
	} else {
		args->args = root;
	}

	*args_r = args;
	return 0;
}

struct mail_search_args *mail_search_build_init(void)
{
	struct mail_search_args *args;
	pool_t pool;

	pool = pool_alloconly_create("mail search args", 4096);
	args = p_new(pool, struct mail_search_args, 1);
	args->pool = pool;
	args->refcount = 1;
	return args;
}

void mail_search_build_add_all(struct mail_search_args *args)
{
	struct mail_search_arg *arg;

	arg = p_new(args->pool, struct mail_search_arg, 1);
	arg->type = SEARCH_ALL;

	arg->next = args->args;
	args->args = arg;
}

void mail_search_build_add_seqset(struct mail_search_args *args,
				  uint32_t seq1, uint32_t seq2)
{
	struct mail_search_arg *arg;

	arg = p_new(args->pool, struct mail_search_arg, 1);
	arg->type = SEARCH_SEQSET;
	p_array_init(&arg->value.seqset, args->pool, 1);
	seq_range_array_add_range(&arg->value.seqset, seq1, seq2);

	arg->next = args->args;
	args->args = arg;
}
