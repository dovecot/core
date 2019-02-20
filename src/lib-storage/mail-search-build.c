/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "charset-utf8.h"
#include "mail-storage-private.h"
#include "mail-search-register.h"
#include "mail-search-parser.h"
#include "mail-search-build.h"


static int mail_search_build_list(struct mail_search_build_context *ctx,
				  struct mail_search_arg **arg_r);

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
		      enum mail_search_arg_type type)
{
	struct mail_search_arg *sarg;
	const char *value;

	sarg = mail_search_build_new(ctx, type);
	if (mail_search_parse_string(ctx->parser, &value) < 0)
		return NULL;
	sarg->value.str = p_strdup(ctx->pool, value);
	return sarg;
}

static int
mail_search_build_key_int(struct mail_search_build_context *ctx,
			  struct mail_search_arg *parent,
			  struct mail_search_arg **arg_r)
{
	struct mail_search_arg *sarg;
	struct mail_search_arg *old_parent = ctx->parent;
	const char *key;
	const struct mail_search_register_arg *reg_arg;
	mail_search_register_fallback_t *fallback;
	int ret;

	ctx->parent = parent;

	if ((ret = mail_search_parse_key(ctx->parser, &key)) <= 0)
		return ret;

	if (strcmp(key, MAIL_SEARCH_PARSER_KEY_LIST) == 0) {
		if (mail_search_build_list(ctx, &sarg) < 0)
			return -1;
		if (sarg->value.subargs == NULL) {
			ctx->_error = "No search parameters inside list";
			return -1;
		}

		ctx->parent = old_parent;
		*arg_r = sarg;
		return 1;
	}
	key = t_str_ucase(key);

	reg_arg = mail_search_register_find(ctx->reg, key);
	if (reg_arg != NULL)
		sarg = reg_arg->build(ctx);
	else if (mail_search_register_get_fallback(ctx->reg, &fallback))
		sarg = fallback(ctx, key);
	else {
		sarg = NULL;
		ctx->_error = p_strconcat(ctx->pool, "Unknown argument ",
					  key, NULL);
	}

	ctx->parent = old_parent;
	*arg_r = sarg;
	return sarg == NULL ? -1 : 1;
}

int mail_search_build_key(struct mail_search_build_context *ctx,
			  struct mail_search_arg *parent,
			  struct mail_search_arg **arg_r)
{
	int ret;

	ret = mail_search_build_key_int(ctx, parent, arg_r);
	if (ret <= 0) {
		if (ret == 0)
			ctx->_error = "Missing argument";
		return -1;
	}
	return 0;
}

static int mail_search_build_list(struct mail_search_build_context *ctx,
				  struct mail_search_arg **arg_r)
{
	struct mail_search_arg *sarg, **subargs;
	enum mail_search_arg_type cur_type = SEARCH_SUB;
	int ret;

	sarg = p_new(ctx->pool, struct mail_search_arg, 1);
	sarg->type = cur_type;

	subargs = &sarg->value.subargs;
	while ((ret = mail_search_build_key_int(ctx, sarg, subargs)) > 0) {
		if (cur_type == sarg->type) {
			/* expected type */
		} else if (cur_type == SEARCH_SUB) {
			/* type changed. everything in this list must now
			   belong to this type. */
			cur_type = sarg->type;
		} else {
			ctx->_error =
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

int mail_search_build(struct mail_search_register *reg,
		      struct mail_search_parser *parser, const char **charset,
		      struct mail_search_args **args_r,
		      const char **client_error_r)
{
        struct mail_search_build_context ctx;
	struct mail_search_args *args;
	struct mail_search_arg *root;
	const char *str;
	int ret;

	*args_r = NULL;
	*client_error_r = NULL;

	i_zero(&ctx);
	ctx.args = args = mail_search_build_init();
	ctx.pool = args->pool;
	ctx.reg = reg;
	ctx.parser = parser;
	ctx.charset = p_strdup(ctx.pool, *charset);

	ret = mail_search_build_list(&ctx, &root);
	if (!ctx.charset_checked && ret == 0) {
		/* make sure we give an error message if charset is invalid */
		ret = mail_search_build_get_utf8(&ctx, "", &str);
	}
	if (ret < 0) {
		*client_error_r = ctx._error != NULL ? t_strdup(ctx._error) :
			t_strdup(mail_search_parser_get_error(parser));
		if (ctx.unknown_charset)
			*charset = NULL;
		pool_unref(&args->pool);
		return -1;
	}

	if (root->type == SEARCH_SUB && !root->match_not) {
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

struct mail_search_arg *
mail_search_build_add(struct mail_search_args *args,
		      enum mail_search_arg_type type)
{
	struct mail_search_arg *arg;

	arg = p_new(args->pool, struct mail_search_arg, 1);
	arg->type = type;

	arg->next = args->args;
	args->args = arg;
	return arg;
}

void mail_search_build_add_all(struct mail_search_args *args)
{
	(void)mail_search_build_add(args, SEARCH_ALL);
}

void mail_search_build_add_seqset(struct mail_search_args *args,
				  uint32_t seq1, uint32_t seq2)
{
	struct mail_search_arg *arg;

	arg = mail_search_build_add(args, SEARCH_SEQSET);

	p_array_init(&arg->value.seqset, args->pool, 1);
	seq_range_array_add_range(&arg->value.seqset, seq1, seq2);
}

int mail_search_build_get_utf8(struct mail_search_build_context *ctx,
			       const char *input, const char **output_r)
{
	int ret;

	T_BEGIN {
		string_t *utf8 = t_str_new(128);
		enum charset_result result;

		if (charset_to_utf8_str(ctx->charset, NULL,
					input, utf8, &result) < 0) {
			/* unknown charset */
			ctx->_error = "Unknown charset";
			ctx->unknown_charset = TRUE;
			ret = -1;
		} else if (result != CHARSET_RET_OK) {
			/* invalid key */
			ctx->_error = "Invalid search key";
			ret = -1;
		} else {
			*output_r = p_strdup(ctx->pool, str_c(utf8));
			ret = 0;
		}
	} T_END;

	ctx->charset_checked = TRUE;
	return ret;
}
