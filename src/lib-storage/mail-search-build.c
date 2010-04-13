/* Copyright (c) 2002-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "imap-arg.h"
#include "mail-storage-private.h"
#include "mail-search-register.h"
#include "mail-search-build.h"

#include <stdlib.h>

struct mail_search_arg *
mail_search_build_next(struct mail_search_build_context *ctx,
		       const struct imap_arg **imap_args)
{
	struct mail_search_arg **subargs, *sarg;
	const struct imap_arg *listargs;
	const char *key;
	const struct mail_search_register_arg *reg_arg;
	mail_search_register_fallback_t *fallback;

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

		sarg = p_new(ctx->pool, struct mail_search_arg, 1);
		sarg->type = SEARCH_SUB;
		subargs = &sarg->value.subargs;
		while (!IMAP_ARG_IS_EOL(listargs)) {
			*subargs = mail_search_build_next(ctx, &listargs);
			if (*subargs == NULL)
				return NULL;
			subargs = &(*subargs)->next;
		}

		*imap_args += 1;
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
	return sarg;
}

int mail_search_build_from_imap_args(const struct imap_arg *imap_args,
				     const char *charset,
				     struct mail_search_args **args_r,
				     const char **error_r)
{
        struct mail_search_build_context ctx;
	struct mail_search_args *args;
	struct mail_search_arg **sargs;

	*args_r = NULL;
	*error_r = NULL;

	args = mail_search_build_init();
	args->charset = p_strdup(args->pool, charset);

	memset(&ctx, 0, sizeof(ctx));
	ctx.pool = args->pool;
	ctx.reg = mail_search_register_imap;

	sargs = &args->args;
	while (!IMAP_ARG_IS_EOL(imap_args)) {
		*sargs = mail_search_build_next(&ctx, &imap_args);
		if (*sargs == NULL) {
			*error_r = t_strdup(ctx.error);
			pool_unref(&args->pool);
			return -1;
		}
		sargs = &(*sargs)->next;
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
